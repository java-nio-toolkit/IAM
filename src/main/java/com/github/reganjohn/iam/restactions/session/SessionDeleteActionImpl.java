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

import com.github.adamorgan.jnt.api.exceptions.DetachedEntityException;
import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException.SchemaError;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.BuilderExample;
import com.github.reganjohn.iam.Routes;
import com.github.reganjohn.iam.ThreadLocalReason;
import com.github.reganjohn.iam.exceptions.DataObjectParsingException;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.reganjohn.iam.UserAction.*;

public class SessionDeleteActionImpl extends AbstractSessionActionImpl
{
    public SessionDeleteActionImpl(@Nonnull BuilderExample api)
    {
        super(api, Routes.Session.REMOVE_SESSION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleUniqueID(context, request, new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull List<SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueID(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(SESSION_ID, ex, schemaErrors);
        }
        finally
        {
            handleException(context, request, schemaErrors);
        }
    }

    private void checkUniqueID(Map<String, String> params)
    {
        String id = params.get(SESSION_ID);
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, Helpers.format("The \"%s\" value is not uuid.", SESSION_ID));
    }

    private void handleException(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull List<SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(50035, "Invalid Form Body", errors);
        else
            handleInternally(context, request);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(json.getSubject());
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID sessionId = UUID.fromString(params.get(SESSION_ID));
        api.retrieveSessionCount(userId)
                
                .queue(count ->
                {
                    if (count == 1)
                        throw new IllegalStateException("Cannot close the last active session as at least one session must remain active.");
                    else if (count >= 1)
                        deleteSessionById(context, userId, sessionId);
                    else
                        throw new DetachedEntityException(10012, "Unknown Session");
                });
    }

    private void deleteSessionById(@Nonnull ChannelHandlerContext context, @Nonnull UUID userId, @Nonnull UUID sessionId)
    {
        this.api.deleteSessionById(userId, sessionId)
                
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }
}
