/*
 * Copyright 2026 Ada Morgan, John Regan and the JNT contributors
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

package com.github.reganjohn.iam.exceptions;

import com.github.adamorgan.jnt.api.exceptions.ParsingException;

import javax.annotation.Nonnull;

public class DataObjectParsingException extends ParsingException
{
    private final String errorCode;
    private final String meaning;

    public DataObjectParsingException(@Nonnull String code, @Nonnull String meaning)
    {
        super(code + ": " + meaning);
        this.errorCode = code;
        this.meaning = meaning;
    }

    @Nonnull
    public String getErrorCode()
    {
        return errorCode;
    }

    @Nonnull
    public String getMeaning()
    {
        return meaning;
    }
}
