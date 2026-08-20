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

package com.github.reganjohn.iam.internal.requests.restactions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.restactions.AbstractOverrideAction;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.StringJoiner;

public abstract class AbstractOverrideActionImpl extends RestActionImpl implements AbstractOverrideAction
{
    protected final IAMImpl api;

    public AbstractOverrideActionImpl(@Nonnull IAMImpl api, @Nonnull Route route)
    {
        super(route);
        this.api = api;
    }

    @Nonnull
    @Override
    public IAMImpl getIAM()
    {
        return api;
    }

    protected void handleErrorResponse(@Nonnull String name, @Nonnull DataObjectParsingException exception,
                                       @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        InvalidResponseException.ErrorCode errorCode = new InvalidResponseException.ErrorCode(exception.getErrorCode(), exception.getMeaning());
        InvalidResponseException.SchemaError schemaError = new InvalidResponseException.SchemaError(name, Collections.singletonList(errorCode));
        errors.add(schemaError);
    }

    @Nonnull
    protected ErrorResponseException createErrorResponse(@Nonnull String location, @Nonnull String code,
                                                         @Nonnull String meaning)
    {
        InvalidResponseException.ErrorCode errorCode = new InvalidResponseException.ErrorCode(code, meaning);
        InvalidResponseException.SchemaError schemaError = new InvalidResponseException.SchemaError(location, Collections.singletonList(errorCode));
        return new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, schemaError);
    }

    @Nonnull
    protected DataObjectParsingException createParsingException(@Nonnull String location, @Nonnull SignType type)
    {
        return createParsingException(location, Collections.singletonList(type.getType().name()));
    }

    @Nonnull
    protected DataObjectParsingException createParsingException(@Nonnull String location,
                                                                @Nonnull Collection<String> set)
    {
        StringJoiner joiner = new StringJoiner(", ");
        for (String type : set)
            joiner.add("'" + type + "'");
        return new DataObjectParsingException(BASE_TYPE_CHOICES,
                Helpers.format("Value of field \"%s\" must be one of (%s).", location, joiner));
    }
}
