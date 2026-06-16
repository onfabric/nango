import { Encryption } from '@nangohq/utils';

import { envs } from '../env.js';

import type { EncryptedRecordData, FormattedRecord, UnencryptedRecordData } from '../types.js';

let encryption: Encryption | null = null;

function getEncryption(): Encryption {
    if (!encryption) {
        const encryptionKey = envs.NANGO_ENCRYPTION_KEY;
        if (!encryptionKey) {
            throw new Error('NANGO_ENCRYPTION_KEY is not set');
        }
        encryption = new Encryption(encryptionKey);
    }
    return encryption;
}

function isEncrypted(data: UnencryptedRecordData | EncryptedRecordData): data is EncryptedRecordData {
    return !!data && 'encryptedValue' in data;
}

export async function decryptRecordData(record: FormattedRecord): Promise<UnencryptedRecordData> {
    const encryptionManager = getEncryption();
    const { json } = record;
    if (isEncrypted(json)) {
        const { encryptedValue, iv, authTag } = json;
        const decryptedString = await encryptionManager.decryptAsync(encryptedValue, iv, authTag);
        return JSON.parse(decryptedString) as UnencryptedRecordData;
    }
    return json;
}

export function encryptRecords(records: FormattedRecord[]): FormattedRecord[] {
    // Store records as plaintext when encryption is disabled, OR when records are
    // explicitly kept plaintext (NANGO_RECORDS_PLAINTEXT) so the brain can read
    // nango_records over SQL while credentials/configs/secrets stay encrypted under
    // NANGO_ENCRYPTION_KEY. decryptRecordData() detects unencrypted rows (no
    // `encryptedValue`) and returns them as-is, so mixed plaintext/encrypted rows
    // are safe.
    if (!envs.NANGO_ENCRYPTION_KEY || process.env['NANGO_RECORDS_PLAINTEXT'] === 'true') {
        return records;
    }
    const encryptionManager = getEncryption();
    const encryptedDataRecords: FormattedRecord[] = Object.assign([], records);

    for (const record of encryptedDataRecords) {
        const [encryptedValue, iv, authTag] = encryptionManager.encryptSync(JSON.stringify(record.json));
        record.json = { encryptedValue, iv, authTag };
    }

    return encryptedDataRecords;
}
