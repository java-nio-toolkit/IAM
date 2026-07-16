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
    UNKNOWN_SIGNER(10010, "Unknown Signer"),
    UNKNOWN_ACCESS(10011, "Unknown Access"),
    UNKNOWN_SESSION(10012, "Unknown Session"),
    UNKNOWN_USER(10013, "Unknown User"),
    UNKNOWN_APPLICATION(10014, "Unknown Application"),

    MAX_SESSIONS(30001, "Maximum number of Sessions reached (10)"),
    MAX_APPLICATION(30002, "Maximum number of Applications reached (32)"),
    MAX_ACCESS_APPLICATION(30015, "Maximum number of access in a application (10)"),

    UNAUTHORIZED(40001, "Unauthorized"),
    SESSION_ALREADY_EXISTS(40122, "An session with that access object already exists"),
    ACCESS_ALREADY_EXISTS(40123, "An access object with that already exists"),
    APPLICATION_ALREADY_EXISTS(40124, "An application with that access object already exists"),

    CANNOT_CLOSE_SINGLE_SESSION(50008, "The single remaining session cannot be closed."),
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
