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

package com.github.reganjohn.iam.restactions.self;

import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException.SchemaError;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.reganjohn.iam.BuilderExample;
import com.github.reganjohn.iam.Routes;
import com.github.reganjohn.iam.ThreadLocalReason;
import com.github.reganjohn.iam.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.utils.users.UserEditData;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SelfUserEditActionImpl extends AbstractSelfUserActionImpl implements SelfUserEditAction
{
    public static final List<String> MAJOR_PARAMETER_NAMES =
            Helpers.listOf("username", "flags");

    public SelfUserEditActionImpl(@Nonnull BuilderExample api)
    {
        super(api, Routes.Self.MODIFY_SELF);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new ErrorResponseException(50036, "Only dictionaries may be used in a DictType");
        else
            handleUser(context, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleUser(@Nonnull ChannelHandlerContext context,
                            @Nonnull DataObject rawData, @Nonnull List<SchemaError> schemaErrors)
    {
        rawData.retain(MAJOR_PARAMETER_NAMES);
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUser(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("username", ex, schemaErrors);
        }
        finally
        {
            handleFlags(context, rawData, schemaErrors);
        }
    }

    private void handleFlags(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawData,
                             @Nonnull List<SchemaError> schemaErrors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkFlags(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("username", ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, rawData, schemaErrors);
        }
    }

    private void checkUser(@Nonnull DataObject body)
    {
        if (!body.hasKey(NAME))
            return;
        else if (!body.isType(NAME, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", NAME));
        else if (body.getString(NAME).length() < MIN_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MIN,
                    Helpers.format("The \"%s\" value may not be less than %f characters.", NAME, MIN_NAME_LENGTH));
        else if (body.getString(NAME).length() > MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"%s\" may not be longer than %d characters.", NAME, MAX_NAME_LENGTH));
    }

    private void checkFlags(DataObject body)
    {
        if (!body.hasKey("flags"))
            return;
        else if (!body.isType("flags", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not number.", NAME));
        else if (body.getInt(NAME) < 0)
            throw new DataObjectParsingException(NUMBER_TYPE_MIN,
                    Helpers.format("flags value should be greater than or equal to 0.", NAME));
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull DataObject json,
                                  @Nonnull List<SchemaError> errors)
    {
        AccessObjectData objectData = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(objectData.getSubject());
        String username = json.getString(NAME, null);
        int flags = json.getInt("flags", 0);
        UserEditData user = new UserEditData(userId, username, flags);
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(50035, "Invalid Form Body", errors);
        else
            api.editUser(user).queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new ConcurrentHashMap<>()));
    }
}
