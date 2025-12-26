import { z, ZodType } from "zod";
import { NoDeleteOldPolicyConfig } from "./no-delete-old";

export interface GuardrailPolicy {
    evaluate(request: Request<unknown, IncomingRequestCfProperties>): Promise<GuardrailViolation | null>;
}

export type GuardrailViolation = {
    violation: string
}

/*
 * Corresponding config for each object path pattern in regex. First match wins.
*/
export const GuardrailPolicyConfigPerPattern = <T extends ZodType>(policy: T) => z.array(z.object({
    pattern: z.string(),
    config: policy
}))
export const GuardrailConfig = z.object({
    noDeleteOld: GuardrailPolicyConfigPerPattern(NoDeleteOldPolicyConfig)
})
export type GuardrailConfig = z.infer<typeof GuardrailConfig>

/**
 * Error calling upstream when evaluating guardrails
 */
export class UpstreamError extends Error {
    code: string
    constructor(code: string, message: string) {
        super(message)
        this.code = code
    }
}