import crypto from 'crypto';

import * as z from 'zod';

import db from '@nangohq/database';
import { acceptInvitation, accountService, getInvitation, pbkdf2, userService } from '@nangohq/shared';
import { flagHasUsage, report, requireEmptyQuery, zodErrorToHTTP } from '@nangohq/utils';

import { envs } from '../../../env.js';
import { asyncWrapper } from '../../../utils/asyncWrapper.js';
import { linkBillingCustomer, linkBillingFreeSubscription } from '../../../utils/billing.js';

import type { Knex } from '@nangohq/database';
import type { DBTeam, DBUser, PostSignup, Role } from '@nangohq/types';

export const passwordSchema = z
    .string()
    .min(8)
    .max(64)
    .refine((value) => {
        return value.match(/[A-Z]+/) && value.match(/[0-9]/) && value.match(/[^a-zA-Z0-9]/);
    }, 'Password should be least 8 characters with uppercase, a number and a special character');

const validation = z
    .object({
        email: z.string().email(),
        password: passwordSchema,
        name: z.string(),
        token: z.string().uuid().optional(),
        foundUs: z.string().optional()
    })
    .strict();

const bootstrapSignupLockKey = 'nango_bootstrap_signup';
const invitationRequiredMessage = 'An account already exists. Ask an administrator to invite you.';

function emailsMatch(first: string, second: string): boolean {
    return first.trim().toLowerCase() === second.trim().toLowerCase();
}

async function hashPassword(password: string): Promise<{ hashedPassword: string; salt: string }> {
    const salt = crypto.randomBytes(16).toString('base64');
    const hashedPassword = (await pbkdf2(password, salt, 310000, 32, 'sha256')).toString('base64');

    return { hashedPassword, salt };
}

async function createUser({
    email,
    name,
    accountId,
    hashedPassword,
    salt,
    role,
    trx
}: {
    email: string;
    name: string;
    accountId: number;
    hashedPassword: string;
    salt: string;
    role: Role;
    trx?: Knex;
}): Promise<DBUser | null> {
    return await userService.createUser({
        email,
        name,
        hashed_password: hashedPassword,
        salt,
        account_id: accountId,
        email_verified: true,
        role,
        ...(trx ? { trx } : {})
    });
}

export const signup = asyncWrapper<PostSignup>(async (req, res) => {
    const emptyQuery = requireEmptyQuery(req);
    if (emptyQuery) {
        res.status(400).send({ error: { code: 'invalid_query_params', errors: zodErrorToHTTP(emptyQuery.error) } });
        return;
    }

    const val = validation.safeParse(req.body);
    if (!val.success) {
        res.status(400).send({
            error: { code: 'invalid_body', errors: zodErrorToHTTP(val.error) }
        });
        return;
    }

    const { email, password, name, token, foundUs }: PostSignup['Body'] = val.data;

    const existingUser = await userService.getUserByEmail(email);
    if (existingUser) {
        if (!existingUser.email_verified) {
            res.status(400).send({
                error: {
                    code: 'email_not_verified',
                    message: 'A user already exists with this email address but the address is not verified.'
                }
            });
        } else {
            res.status(400).send({
                error: {
                    code: 'user_already_exists',
                    message: 'User with this email already exists'
                }
            });
        }
        return;
    }

    const { hashedPassword, salt } = await hashPassword(password);
    let account: DBTeam | null;
    let user: DBUser | null;
    let invitationRole: Role = envs.DEFAULT_USER_ROLE;
    if (token) {
        const validToken = await getInvitation(token);
        if (!validToken) {
            res.status(400).send({ error: { code: 'invalid_invite_token', message: 'The token used was found to be invalid.' } });
            return;
        }

        if (!emailsMatch(validToken.email, email)) {
            res.status(400).send({ error: { code: 'invalid_invite_token', message: 'The token used was found to be invalid.' } });
            return;
        }

        account = await accountService.getAccountById(db.knex, validToken.account_id);
        if (!account) {
            res.status(500).send({ error: { code: 'server_error', message: 'Failed to get team' } });
            return;
        }

        invitationRole = validToken.role;
        const invitedAccount = account;
        user = await db.knex.transaction(async (trx) => {
            const created = await createUser({ email, name, accountId: invitedAccount.id, hashedPassword, salt, role: invitationRole, trx });
            if (!created) {
                return null;
            }

            await acceptInvitation(token, trx);
            return created;
        });
    } else {
        if (!envs.AUTH_ALLOW_SIGNUP) {
            res.status(403).send({ error: { code: 'forbidden', message: 'Signup is disabled.' } });
            return;
        }

        const result = await db.knex.transaction(async (trx) => {
            await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [bootstrapSignupLockKey]);

            if (await userService.hasAnyUser(trx)) {
                return { blocked: true as const };
            }

            const createdAccount = await accountService.createAccount({ name, email, foundUs, trx });
            if (!createdAccount) {
                return { error: 'error_creating_account' as const };
            }

            const createdUser = await createUser({ email, name, accountId: createdAccount.id, hashedPassword, salt, role: envs.DEFAULT_USER_ROLE, trx });
            if (!createdUser) {
                return { error: 'error_creating_user' as const };
            }

            return { account: createdAccount, user: createdUser };
        });

        if ('blocked' in result) {
            res.status(403).send({ error: { code: 'invite_required', message: invitationRequiredMessage } });
            return;
        }

        if ('error' in result && result.error === 'error_creating_account') {
            res.status(500).send({
                error: { code: 'error_creating_account', message: 'There was a problem creating the account. Please reach out to support.' }
            });
            return;
        }

        if ('error' in result && result.error === 'error_creating_user') {
            res.status(500).send({ error: { code: 'error_creating_user', message: 'There was a problem creating the user. Please reach out to support.' } });
            return;
        }

        account = result.account;
        user = result.user;
    }

    if (!user) {
        res.status(500).send({ error: { code: 'error_creating_user', message: 'There was a problem creating the user. Please reach out to support.' } });
        return;
    }

    if (!token && flagHasUsage) {
        const linkOrbCustomerRes = await linkBillingCustomer(account, user);
        if (linkOrbCustomerRes.isErr()) {
            report(linkOrbCustomerRes.error);
        } else {
            const linkOrbSubscriptionRes = await linkBillingFreeSubscription(account);
            if (linkOrbSubscriptionRes.isErr()) {
                report(linkOrbSubscriptionRes.error);
            }
        }
    }

    req.login(user, function (err) {
        if (err) {
            res.status(500).send({ error: { code: 'server_error', message: 'There was a problem logging in the user. Please reach out to support.' } });
            return;
        }

        res.status(200).send({ data: { uuid: user.uuid, verified: true } });
    });
});
