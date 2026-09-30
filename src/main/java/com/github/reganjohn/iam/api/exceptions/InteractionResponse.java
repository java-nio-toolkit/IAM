/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.api.exceptions;

import com.github.adamorgan.jnt.api.requests.StatusReason;

import javax.annotation.Nonnull;

public enum InteractionResponse
{
    INVALID_REQUEST("invalid_request", StatusReason.BAD_REQUEST),
    INVALID_CLIENT("invalid_client", StatusReason.UNAUTHORIZED),
    INVALID_INTERACTION("invalid_interaction", StatusReason.FORBIDDEN),
    INVALID_FLAG("invalid_flag", StatusReason.BAD_REQUEST),
    INVALID_CONTINUATION("invalid_continuation", StatusReason.UNAUTHORIZED),
    USER_DENIED("user_denied", StatusReason.FORBIDDEN),
    REQUEST_DENIED("request_denied", StatusReason.FORBIDDEN),
    UNKNOWN_INTERACTION("unknown_interaction", StatusReason.NOT_FOUND),
    TOO_MANY_ATTEMPTS("too_many_attempts", StatusReason.TOO_MANY_REQUESTS);

    private final String code;
    private final StatusReason status;

    InteractionResponse(@Nonnull String code, @Nonnull StatusReason status)
    {
        this.code = code;
        this.status = status;
    }

    @Nonnull
    public String getCode()
    {
        return code;
    }

    @Nonnull
    public StatusReason getStatus()
    {
        return status;
    }
}
