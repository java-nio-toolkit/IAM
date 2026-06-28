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

package com.github.reganjohn.iam.internal.requests.restactions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.reganjohn.iam.api.BuilderExample;
import com.github.reganjohn.iam.api.requests.restactions.UserAction;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collections;
import java.util.List;

public abstract class AbstractUserActionImpl extends RestActionImpl implements UserAction
{
    protected final BuilderExample api;

    public AbstractUserActionImpl(@Nonnull BuilderExample api, @Nonnull Route route)
    {
        super(route);
        this.api = api;
    }

    protected void handleErrorResponse(@Nonnull DataObjectParsingException exception,
                                       @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        handleErrorResponse(null, exception, schemaErrors);
    }

    protected void handleErrorResponse(@Nullable String name, @Nonnull DataObjectParsingException exception,
                                       @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        InvalidResponseException.ErrorCode errorCode = new InvalidResponseException.ErrorCode(exception.getErrorCode(), exception.getMeaning());
        InvalidResponseException.SchemaError schemaError = new InvalidResponseException.SchemaError(name, Collections.singletonList(errorCode));
        schemaErrors.add(schemaError);
    }
}
