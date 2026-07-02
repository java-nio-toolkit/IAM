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

package com.github.reganjohn.iam.internal.requests.restactions.self;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.requests.restactions.self.SelfUserEditAction;
import com.github.reganjohn.iam.api.utils.users.UserEditData;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SelfUserEditActionImpl extends AbstractSelfUserActionImpl implements SelfUserEditAction
{
    public SelfUserEditActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Self.MODIFY_SELF);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleName(context, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleName(@Nonnull ChannelHandlerContext context,
                            @Nonnull DataObject rawData,
                            @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkName(rawData);
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

    private void checkName(@Nonnull DataObject body)
    {
        if (!body.hasKey("username"))
            return;
        else if (!body.isType("username", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"username\" value is not string.");
        else if (body.getString("username").length() < MIN_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MIN, Helpers.format("The \"username\" value may not be less than %f characters.", MIN_NAME_LENGTH));
        else if (body.getString("username").length() > MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX, Helpers.format("The \"username\" may not be longer than %d characters.", MAX_NAME_LENGTH));
    }

    private void handleFlags(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawData,
                             @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
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

    private void checkFlags(@Nonnull DataObject body)
    {
        if (!body.hasKey("flags"))
            return;
        else if (!body.isType("flags", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"flags\" is not number.");
        else if (body.getInt("flags") < 0)
            throw new DataObjectParsingException(NUMBER_TYPE_MIN, Helpers.format("Value \"flags\" should be greater than or equal to 0."));
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull DataObject json,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        AccessObjectData objectData = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(objectData.getSubject());
        api.retrieveUserById(userId).queue(user ->
        {
            //todo: add a check for permissions to modify flags
            handleInternally(context, user, json, errors);
        });
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull User user,
                                  @Nonnull DataObject json,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        String name = json.getString("username");
        UserEditData data = new UserEditData(user.getUniqueId());
        if (json.hasKey("username", DataType.STRING))
            data.setName(name);
        if (json.hasKey("flags", DataType.INT))
            data.setFlags(json.getInt("flags"));
        user.edit(data).queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new ConcurrentHashMap<>()));
    }
}
