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

import javax.annotation.Nonnull;

public enum InteractionResponse
{
    INVALID_REQUEST("invalid_request"),
    INVALID_FLAG("invalid_flag"),
    INVALID_CLIENT("invalid_client"),
    INVALID_CONTINUATION("invalid_continuation"),
    UNKNOWN_INTERACTION("unknown_interaction"),
    TOO_MANY_ATTEMPTS("too_many_attempts"),
    INVALID_INTERACTION("invalid_interaction"),
    USER_DENIED("user_denied"),
    REQUEST_DENIED("request_denied");

    private final String code;

    InteractionResponse(@Nonnull String code)
    {
        this.code = code;
    }

    @Nonnull
    public String getCode()
    {
        return code;
    }
}
