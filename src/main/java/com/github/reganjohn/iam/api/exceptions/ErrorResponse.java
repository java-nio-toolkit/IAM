/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.api.exceptions;

import javax.annotation.Nonnull;

public enum ErrorResponse
{
    UNKNOWN_SIGNER(10011, "Unknown Signer"),
    UNKNOWN_SESSION(10012, "Unknown Session"),
    UNKNOWN_USER(10013, "Unknown User"),

    MAX_SESSIONS(30001, "Maximum number of Sessions reached (10)"),

    UNAUTHORIZED(40001, "Unauthorized"),
    SESSION_ALREADY_EXISTS(40122, "An session with that key already exists"),

    INVALID_TOKEN(50014, "Invalid Authentication Token"),
    INVALID_FORM_URL(50034, "Invalid Form URL"),
    INVALID_FORM_BODY(50035, "Invalid Form Body"),
    INVALID_FROM_OBJECT_BODY(50036, "Only dictionaries may be used in a DictType"),

    SERVER_ERROR(0, "Oops! We've encountered an internal server error! Not good!");

    private final int code;
    private final String meaning;

    ErrorResponse(int code, String meaning)
    {
        this.code = code;
        this.meaning = meaning;
    }

    public int getCode()
    {
        return code;
    }

    @Nonnull
    public String getMeaning()
    {
        return meaning;
    }

    @Override
    public String toString()
    {
        return code + ": " + meaning;
    }
}
