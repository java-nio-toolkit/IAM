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

package com.github.reganjohn.iam.restactions.session;

import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException.ErrorCode;
import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException.SchemaError;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.BuilderExample;
import com.github.reganjohn.iam.entities.Session;
import com.github.reganjohn.iam.exceptions.DataObjectParsingException;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.StringJoiner;

import static com.github.reganjohn.iam.UserAction.BASE_TYPE_CHOICES;

public abstract class AbstractSessionActionImpl extends RestActionImpl implements SessionAction
{
    protected static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");
    protected final BuilderExample api;

    public AbstractSessionActionImpl(BuilderExample api, @Nonnull Route route)
    {
        super(route);
        this.api = api;
    }

    protected void handleErrorResponse(@Nonnull String name, @Nonnull DataObjectParsingException exception,
                                       @Nonnull List<SchemaError> schemaErrors)
    {
        ErrorCode errorCode = new ErrorCode(exception.getErrorCode(), exception.getMeaning());
        SchemaError schemaError = new SchemaError(name, Collections.singletonList(errorCode));
        schemaErrors.add(schemaError);
    }

    @Nonnull
    protected ErrorResponseException createErrorResponse(@Nonnull String location, @Nonnull String code, @Nonnull String meaning)
    {
        ErrorCode errorCode = new ErrorCode(code, meaning);
        SchemaError schemaError = new SchemaError(location, Collections.singletonList(errorCode));
        return new ErrorResponseException(50035, "Invalid Form Body", schemaError);
    }

    @Nonnull
    protected DataObjectParsingException createParsingException(@Nonnull String location, @Nonnull SignType signType)
    {
        return createParsingException(location, Collections.singletonList(signType.getType().name()));
    }

    @Nonnull
    protected DataObjectParsingException createParsingException(@Nonnull String location, @Nonnull Collection<String> set)
    {
        StringJoiner joiner = new StringJoiner(", ");
        for (String type : set)
            joiner.add("'" + type + "'");
        return new DataObjectParsingException(BASE_TYPE_CHOICES,
                Helpers.format("Value of field \"%s\" must be one of (%s).", location, joiner));
    }

    @Nonnull
    protected DataObject fromJSON(@Nonnull Session session)
    {
        DataObject rawUser = DataObject.empty()
                .put("user_id", session.getUserId());

        if (Helpers.nonEmpty(session.getUserAgent()))
            rawUser.put("user_agent", session.getUserAgent());

        DataObject json = DataObject.empty()
                .put("session_id", session.getUniqueId());

        return json
                .put("user", rawUser)
                .put("jwk", session.getAccessEntry())
                .put("flags", session.getFlagsRaw())
                .toData();
    }
}
