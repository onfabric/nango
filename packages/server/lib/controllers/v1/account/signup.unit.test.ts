import crypto from 'node:crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { roles } from '@nangohq/utils';

import { signup } from './signup.js';
import { envs } from '../../../env.js';

import type * as NangoUtils from '@nangohq/utils';
import type { Request, Response } from 'express';

const {
    mockAcceptInvitation,
    mockGetInvitation,
    mockGetPlan,
    mockCreateAccount,
    mockGetAccountById,
    mockGetUserByEmail,
    mockHasAnyUser,
    mockPbkdf2,
    mockCreateUser,
    mockTransaction,
    mockTrx
} = vi.hoisted(() => {
    return {
        mockAcceptInvitation: vi.fn(),
        mockGetInvitation: vi.fn(),
        mockGetPlan: vi.fn(),
        mockCreateAccount: vi.fn(),
        mockGetAccountById: vi.fn(),
        mockGetUserByEmail: vi.fn(),
        mockHasAnyUser: vi.fn(),
        mockPbkdf2: vi.fn(),
        mockCreateUser: vi.fn(),
        mockTransaction: vi.fn(),
        mockTrx: {
            raw: vi.fn()
        }
    };
});

vi.mock('@nangohq/database', () => ({
    default: { knex: { transaction: mockTransaction } }
}));

vi.mock('@nangohq/shared', () => ({
    acceptInvitation: mockAcceptInvitation,
    accountService: {
        createAccount: mockCreateAccount,
        getAccountById: mockGetAccountById
    },
    getInvitation: mockGetInvitation,
    getPlan: mockGetPlan,
    pbkdf2: mockPbkdf2,
    userService: {
        getUserByEmail: mockGetUserByEmail,
        hasAnyUser: mockHasAnyUser,
        createUser: mockCreateUser
    }
}));

vi.mock('@nangohq/utils', async () => {
    const actual: typeof NangoUtils = await vi.importActual('@nangohq/utils');

    return {
        ...actual,
        flagHasPlan: false,
        flagHasUsage: false
    };
});

const nonDefaultRole = roles.find((role) => role !== envs.DEFAULT_USER_ROLE);

if (!nonDefaultRole) {
    throw new Error('Expected a non-default role for signup tests');
}

describe('signup', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockAcceptInvitation.mockResolvedValue(undefined);
        mockTransaction.mockImplementation((callback) => callback(mockTrx));
        mockTrx.raw.mockResolvedValue(undefined);
        mockPbkdf2.mockResolvedValue(Buffer.from('hashed-password'));
        mockCreateAccount.mockResolvedValue({ id: 7 });
        mockGetAccountById.mockResolvedValue({ id: 7 });
        mockGetUserByEmail.mockResolvedValue(null);
        mockHasAnyUser.mockResolvedValue(false);
        mockCreateUser.mockResolvedValue({ uuid: crypto.randomUUID(), id: 11, account_id: 7, role: nonDefaultRole });
    });

    it('preserves the invited role at signup when plan mode is disabled', async () => {
        const invitationToken = crypto.randomUUID();
        const email = 'invitee@example.com';

        mockGetInvitation.mockResolvedValue({
            token: invitationToken,
            email,
            account_id: 7,
            role: nonDefaultRole
        });

        const req = {
            body: { email, name: 'Invited User', password: 'Password123!', token: invitationToken },
            query: {},
            route: { path: '/api/v1/account/signup' },
            originalUrl: '/api/v1/account/signup',
            header: vi.fn(),
            login: vi.fn((_user: unknown, callback: (err?: Error) => void) => callback())
        } as unknown as Request;
        const status = vi.fn().mockReturnThis();
        const send = vi.fn().mockReturnThis();
        const res = {
            status,
            send
        } as unknown as Response;

        const next = vi.fn();

        await signup(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(mockGetUserByEmail).toHaveBeenCalledWith(email);
        expect(mockGetInvitation).toHaveBeenCalledWith(invitationToken);
        expect(mockGetAccountById).toHaveBeenCalledWith({ transaction: mockTransaction }, 7);
        expect(mockGetPlan).not.toHaveBeenCalled();
        expect(mockAcceptInvitation).toHaveBeenCalledWith(invitationToken, mockTrx);
        expect(mockPbkdf2).toHaveBeenCalled();
        expect(mockCreateUser).toHaveBeenCalledWith(
            expect.objectContaining({
                email,
                account_id: 7,
                role: nonDefaultRole
            })
        );
        expect(status).toHaveBeenCalledWith(200);
        const payload = send.mock.calls[0]?.[0] as { data: { uuid: string; verified: boolean } } | undefined;

        expect(payload?.data.verified).toBe(true);
        expect(typeof payload?.data.uuid).toBe('string');
    });

    it('auto-verifies regular signups and logs them in', async () => {
        const email = 'new-user@example.com';
        const login = vi.fn((_user: unknown, callback: (err?: Error) => void) => callback());

        const req = {
            body: { email, name: 'New User', password: 'Password123!' },
            query: {},
            route: { path: '/api/v1/account/signup' },
            originalUrl: '/api/v1/account/signup',
            header: vi.fn(),
            login
        } as unknown as Request;
        const status = vi.fn().mockReturnThis();
        const send = vi.fn().mockReturnThis();
        const res = {
            status,
            send
        } as unknown as Response;

        const next = vi.fn();

        await signup(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(mockCreateAccount).toHaveBeenCalledWith(expect.objectContaining({ name: 'New User', email, foundUs: undefined, trx: mockTrx }));
        expect(mockCreateUser).toHaveBeenCalledWith(
            expect.objectContaining({
                email,
                account_id: 7,
                email_verified: true,
                role: envs.DEFAULT_USER_ROLE
            })
        );
        expect(login).toHaveBeenCalled();
        expect(status).toHaveBeenCalledWith(200);
        const payload = send.mock.calls[0]?.[0] as { data: { uuid: string; verified: boolean } } | undefined;

        expect(payload?.data.verified).toBe(true);
        expect(typeof payload?.data.uuid).toBe('string');
    });

    it('requires an invitation after the first user has signed up', async () => {
        const email = 'second-user@example.com';
        mockHasAnyUser.mockResolvedValue(true);

        const req = {
            body: { email, name: 'Second User', password: 'Password123!' },
            query: {},
            route: { path: '/api/v1/account/signup' },
            originalUrl: '/api/v1/account/signup',
            header: vi.fn(),
            login: vi.fn()
        } as unknown as Request;
        const status = vi.fn().mockReturnThis();
        const send = vi.fn().mockReturnThis();
        const res = {
            status,
            send
        } as unknown as Response;

        const next = vi.fn();

        await signup(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(mockCreateAccount).not.toHaveBeenCalled();
        expect(mockCreateUser).not.toHaveBeenCalled();
        expect(status).toHaveBeenCalledWith(403);
        expect(send).toHaveBeenCalledWith({
            error: { code: 'invite_required', message: 'An account already exists. Ask an administrator to invite you.' }
        });
    });

    it('rejects an invitation signup when the email does not match the invite', async () => {
        const invitationToken = crypto.randomUUID();

        mockGetInvitation.mockResolvedValue({
            token: invitationToken,
            email: 'invitee@example.com',
            account_id: 7,
            role: nonDefaultRole
        });

        const req = {
            body: { email: 'attacker@example.com', name: 'Attacker', password: 'Password123!', token: invitationToken },
            query: {},
            route: { path: '/api/v1/account/signup' },
            originalUrl: '/api/v1/account/signup',
            header: vi.fn(),
            login: vi.fn()
        } as unknown as Request;
        const status = vi.fn().mockReturnThis();
        const send = vi.fn().mockReturnThis();
        const res = {
            status,
            send
        } as unknown as Response;

        const next = vi.fn();

        await signup(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(mockGetAccountById).not.toHaveBeenCalled();
        expect(mockCreateUser).not.toHaveBeenCalled();
        expect(mockAcceptInvitation).not.toHaveBeenCalled();
        expect(status).toHaveBeenCalledWith(400);
        expect(send).toHaveBeenCalledWith({
            error: { code: 'invalid_invite_token', message: 'The token used was found to be invalid.' }
        });
    });
});
