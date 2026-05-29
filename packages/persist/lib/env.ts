import { ENVS, parseEnvs } from '@nangohq/utils';

// Encryption key is optional: when unset, records are stored unencrypted.
export const envs = parseEnvs(ENVS);
