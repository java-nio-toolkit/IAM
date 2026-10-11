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

package com.github.reganjohn.iam.internal.requests.restactions.self;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.self.SelfUserEditAction;
import com.github.reganjohn.iam.api.utils.users.UserEditBuilder;
import com.github.reganjohn.iam.api.utils.users.UserEditData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractUserActionImpl;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class SelfUserEditActionImpl extends AbstractUserActionImpl implements SelfUserEditAction
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

    private void handleName(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawData,
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
            handleAvatarId(context, rawData, schemaErrors);
        }
    }

    private void checkName(@Nonnull DataObject body)
    {
        if (!body.hasKey("username"))
            return;
        else if (!body.isType("username", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"username\" value is not string.");
        else if (body.isEmpty("username"))
            throw new DataObjectParsingException(STRING_TYPE_MIN, "The \"username\" value may not be empty.");
        else if (body.getString("username").length() > User.MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"username\" may not be longer than %d characters.", User.MAX_NAME_LENGTH));
    }

    private void handleAvatarId(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawData,
                            @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkAvatarId(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("avatar_id", ex, schemaErrors);
        }
        finally
        {
            handleFlags(context, rawData, schemaErrors);
        }
    }

    private void checkAvatarId(@Nonnull DataObject body)
    {
        if (!body.hasKey("avatar_id"))
            return;
        else if (!body.isType("avatar_id", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"avatar_id\" value is not string.");
        else if (body.getString("avatar_id").length() > User.AVATAR_CID_MAX_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"avatar_id\" may not be longer than %d characters.", User.AVATAR_CID_MAX_LENGTH));
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
            handleErrorResponse("flags", ex, schemaErrors);
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
            throw new DataObjectParsingException(NUMBER_TYPE_MIN, "Value \"flags\" should be greater than or equal to 0.");
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull DataObject json,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);

        api.retrieveUserById(retrieveSelfUserId(context))
                .flatMap(user -> modify(user, fromData(user, json)))
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    private UserEditData fromData(@Nonnull User user, @Nonnull DataObject data)
    {
        UUID userId = user.getUniqueId();
        String name = data.getString("username", user.getName());
        String avatarId = data.getString("avatar_id", user.getAvatarId());
        long flags = data.getLong("flags", user.getFlagsRaw());
        long base = user.getFlagsRaw() & User.UserFlag.SYSTEM;
        long modifiers = flags & ~User.UserFlag.SYSTEM;
        return new UserEditBuilder()
                .setUserId(userId)
                .setName(name)
                .setAvatarId(avatarId)
                .setUserFlags(base | modifiers)
                .setReplace(true)
                .build();
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> modify(@Nonnull User user, @Nonnull UserEditData data)
    {
        Checks.notNull(user, "User");
        Checks.notNull(data, "UserEditData");
        InteractionMapping map = new InteractionMapping.Builder(data.toMap())
                .put("current_flags", user.getFlagsRaw())
                .build();
        return new InteractionMappingActionImpl<>(api.getJCA(), "UPDATE users.accounts SET username = :username, avatar_id = :avatar_id, flags = :flags WHERE user_id = :user_id IF flags = :current_flags", map)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_USER));
            }
        };
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }
}
