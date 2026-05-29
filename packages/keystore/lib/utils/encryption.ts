import crypto from 'crypto';
import utils from 'node:util';

import { Encryption } from '@nangohq/utils';

import { envs } from './env.js';

const pbkdf2 = utils.promisify(crypto.pbkdf2);

let encryption: Encryption | null = null;

// Fixed pbkdf2 salt used for hashing when encryption is disabled (no key set).
const NO_ENCRYPTION_SALT = 'nango-encryption-disabled';

export function isEncryptionEnabled(): boolean {
    return Boolean(envs.NANGO_ENCRYPTION_KEY);
}

function getEncryptionKey(): string {
    const encryptionKey = envs.NANGO_ENCRYPTION_KEY;
    if (!encryptionKey) {
        throw new Error('NANGO_ENCRYPTION_KEY is not set');
    }
    return encryptionKey;
}

export function getEncryption(): Encryption {
    if (!encryption) {
        const encryptionKey = getEncryptionKey();
        encryption = new Encryption(encryptionKey);
    }
    return encryption;
}

export async function hashValue(val: string): Promise<string> {
    const salt = envs.NANGO_ENCRYPTION_KEY ?? NO_ENCRYPTION_SALT;
    return (await pbkdf2(val, salt, 310000, 32, 'sha256')).toString('base64');
}
