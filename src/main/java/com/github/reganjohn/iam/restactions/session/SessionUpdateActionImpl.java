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
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.BuilderExample;
import com.github.reganjohn.iam.EntityBuilder;
import com.github.reganjohn.iam.Routes;
import com.github.reganjohn.iam.ThreadLocalReason;
import com.github.reganjohn.iam.entities.Session;
import com.github.reganjohn.iam.exceptions.DataObjectParsingException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.adamorgan.jnt.api.managers.ProofObjectManager.JKT;
import static com.github.reganjohn.iam.UserAction.*;

public class SessionUpdateActionImpl extends AbstractSessionActionImpl
{
    public static final MediaType MEDIA_TYPE_ACCESS = MediaType.parse("application/dpop+jwt");

    private static final String ASSERT_TYPE = ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS;

    public SessionUpdateActionImpl(@Nonnull BuilderExample api)
    {
        super(api, Routes.Session.UPDATE_SESSION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleUniqueID(context, request, new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull List<ErrorResponseException.SchemaError> schemaErrors)
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
            handleInternally(context, request, schemaErrors);
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

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull List<ErrorResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(50035, "Invalid Form Body", errors);
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        String subject = json.getSubject();
        UUID userId = UUID.fromString(subject);
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID sessionId = UUID.fromString(params.get(SESSION_ID));
        api.retrieveSessionById(userId, sessionId).queue(session -> handle(context, json, session), context::fireExceptionCaught);
    }

    private void handle(ChannelHandlerContext context, AccessObjectData json, Session session)
    {
        DataObject contextData = json.getContextData();
        if (contextData == null)
            throw new IllegalStateException("The confirmation is required option and cannot be missing!");
        else if (!contextData.hasKey(JKT))
            throw new IllegalArgumentException("The thumbprint is required option and cannot be missing!");
        else if (!contextData.isType(JKT, DataType.STRING))
            throw new IllegalArgumentException("The JWK Thumbprint within the confirmation object must be a string!");
        else if (!Helpers.equals(contextData.getString(JKT), session.getThumbprint(), false))
            throw new IllegalStateException("The access token thumbprint does not match the session thumbprint.");
        else
            handleAccessToken(context);
    }

    private void handleAccessToken(@Nonnull ChannelHandlerContext context)
    {
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            String uniqueId = UUIDv7.randomUUID().toString();
            String issuer = api.getJNT().getIdentifierString();
            String subject = UUIDv7.randomUUID().toString();

            AccessOptionData optionData = new AccessOptionData(snapshot.getUniqueId(), ASSERT_TYPE, manager.getSignType());
            AccessObjectData json = EntityBuilder.createObjectData(uniqueId, issuer, subject, manager, contextData, optionData, snapshot);
            handleSuccess(context, json);
        }
        catch (Exception error)
        {
            context.fireExceptionCaught(error);
        }
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData newAccessData)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), newAccessData.getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
