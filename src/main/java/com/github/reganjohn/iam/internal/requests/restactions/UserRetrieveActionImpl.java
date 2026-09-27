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
import com.github.adamorgan.jnt.api.requests.*;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.UserRetrieveAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class UserRetrieveActionImpl extends AbstractUserActionImpl implements UserRetrieveAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public UserRetrieveActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Users.GET_USER);
    }

    protected UserRetrieveActionImpl(@Nonnull IAMImpl api, @Nonnull Route route)
    {
        super(api, route);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleRequest(context, request, new ArrayList<>());
    }

    protected void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        String userId = request.getRoute().getMajorParameters().get("user_id");
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUserId(userId);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("user_id", ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, userId, schemaErrors);
        }
    }

    public void checkUserId(@Nonnull String id)
    {
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"user_id\" value is not uuid.");
    }

    protected void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull String userId,
                                    @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        else
            api.retrieveUserById(UUID.fromString(userId)).queue(user -> handleSuccess(context, user), context::fireExceptionCaught);
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull User user)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, fromJSON(user), true);
        Response response = new Response(context, StatusReason.OK, new ArrayListValuedHashMap<>(), body);
        context.writeAndFlush(response);
    }

    @Nonnull
    private static ByteBuf fromJSON(@Nonnull User user)
    {
        return DataObject.empty()
                .put("user_id", user.getUniqueId())
                .put("username", user.getName())
                .put("avatar_id", user.getAvatarId())
                .put("flags", user.getFlagsRaw())
                .toBinary();
    }
}
