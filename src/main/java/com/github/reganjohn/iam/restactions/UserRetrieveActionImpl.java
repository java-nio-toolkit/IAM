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

package com.github.reganjohn.iam.restactions;

import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException.SchemaError;
import com.github.adamorgan.jnt.api.requests.*;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.BuilderExample;
import com.github.reganjohn.iam.Routes;
import com.github.reganjohn.iam.ThreadLocalReason;
import com.github.reganjohn.iam.entities.User;
import com.github.reganjohn.iam.exceptions.DataObjectParsingException;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class UserRetrieveActionImpl extends AbstractUserActionImpl implements UserRetrieveAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public UserRetrieveActionImpl(@Nonnull BuilderExample api)
    {
        super(api, Routes.Users.GET_USER);
    }

    protected UserRetrieveActionImpl(@Nonnull BuilderExample api, @Nonnull Route route)
    {
        super(api, route);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        String userId = request.getRoute().getMajorParameters().get(USER_ID);
        handleInternally(context, userId, new ArrayList<>());
    }

    protected void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull String userId,
                                    @Nonnull List<SchemaError> schemaErrors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUser(userId);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(USER_ID, ex, schemaErrors);
        }
        finally
        {
            handleException(context, userId, schemaErrors);
        }
    }

    private void checkUser(@Nonnull String id)
    {
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, Helpers.format("The \"%s\" value is not uuid.", USER_ID));
    }

    private void handleException(@Nonnull ChannelHandlerContext context, @Nonnull String userId,
                                 @Nonnull List<SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(50035, "Invalid Form Body", errors);
        else
            handleInternally(context, userId);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull String userId)
    {
        api.retrieveUserById(UUID.fromString(userId))
                
                .queue(user -> handleSuccess(context, user), context::fireExceptionCaught);
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull User user)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, fromJSON(user), true);
        Response response = new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body);
        context.writeAndFlush(response);
    }

    @Nonnull
    private static ByteBuf fromJSON(@Nonnull User user)
    {
        return DataObject.empty()
                .put("id", user.getId())
                .put("username", user.getName())
                .put("flags", user.getFlagsRaw())
                .toBinary();
    }
}
