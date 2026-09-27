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

package com.github.reganjohn.iam.internal.requests.restactions.sessions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.sessions.SessionDeleteAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractSessionActionImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class SessionDeleteActionImpl extends AbstractSessionActionImpl implements SessionDeleteAction
{
    public SessionDeleteActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.REMOVE_SESSION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleUniqueID(context, request, new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueID(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("session_id", ex, schemaErrors);
        }
        finally
        {
            handleException(context, request, schemaErrors);
        }
    }

    private void checkUniqueID(@Nonnull Map<String, String> params)
    {
        String id = params.get("session_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"session_id\" value is not uuid.");
    }

    private void handleException(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        else
            handleInternally(context, request);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(json.getSubject());
        UUID sessionId = UUID.fromString(request.getRoute().getMajorParameters().get("session_id"));
        api.retrieveUserById(userId)
                .flatMap(User::retrieveSessionCount)
                .map(count -> delete(userId, sessionId, count))
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> delete(@Nonnull UUID userId, @Nonnull UUID sessionId, int count)
    {
        if (count == 1)
            throw new ErrorResponseException(ErrorResponse.CANNOT_CLOSE_SINGLE_SESSION);
        else
            return retrieveSessionById(userId, sessionId).flatMap(Session::delete);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Session> retrieveSessionById(@Nonnull UUID userId, @Nonnull UUID sessionId)
    {
        return api.retrieveUserById(userId).flatMap(user -> user.retrieveSessionById(sessionId));
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new ArrayListValuedHashMap<>()));
    }
}
