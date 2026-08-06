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

package com.github.reganjohn.iam.internal.requests.restactions.session;

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
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.session.SessionUpdateAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.managers.GlobalAccessManagerImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.concurrent.FastThreadLocal;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.adamorgan.jnt.api.managers.ProofObjectManager.JKT;
import static com.github.reganjohn.iam.api.requests.restactions.UserAction.BASE_TYPE_REQUIRED;
import static com.github.reganjohn.iam.api.requests.restactions.UserAction.UUID_TYPE_COERCE;

public class SessionUpdateActionImpl extends AbstractSessionActionImpl implements SessionUpdateAction
{
    public static final MediaType MEDIA_TYPE_ACCESS = MediaType.parse("application/dpop+jwt");

    public final FastThreadLocal<MessageDigest> SHA256 = new FastThreadLocal<>()
    {
        @Override
        protected MessageDigest initialValue() throws Exception
        {
            return MessageDigest.getInstance("SHA-256");
        }
    };

    public SessionUpdateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.UPDATE_SESSION_ACCESS);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleUniqueID(context, request, new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull List<ErrorResponseException.SchemaError> schemaErrors) throws Exception
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
            handleInternally(context, request, schemaErrors);
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

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull List<ErrorResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        String accessToken = request.getHeaders().get("Authorization").split(" ")[1];
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        AccessObjectData json = EntityBuilder.createAccessObject(accessToken);
        MessageDigest messageDigest = SHA256.get();
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            byte[] hash = messageDigest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
            if (!Helpers.equals(json.getThumbprint(), contextData.digest(), false))
                throw new IllegalArgumentException("Provided proof is not in the same public key as access token.");
            else if (!Helpers.equals(IOUtil.encodeURL(hash), data.getAccessTokenHash(), false))
                throw new IllegalArgumentException("Provided proof is not for the same access token.");
            else
                handleInternally(context, request, json, contextData);
        }
        finally
        {
            messageDigest.reset();
        }
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull AccessObjectData json, @Nonnull AccessContextData contextData)
    {
        UUID userId = UUID.fromString(json.getSubject());
        UUID sessionId = UUID.fromString(request.getRoute().getMajorParameters().get("session_id"));
        api.retrieveUserById(userId)
                .flatMap(user -> user.retrieveSessionById(sessionId))
                .flatMap(session -> update(context, contextData, json, session))
                .queue(data -> handleSuccess(context, data), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<AccessObjectData> update(@Nonnull ChannelHandlerContext context,
                                                               @Nonnull AccessContextData data,
                                                               @Nonnull AccessObjectData json, @Nonnull Session session)
    {
        DataObject contextData = json.getContextData();
        if (json.getActor() != null)
            throw new ErrorResponseException(ErrorResponse.APPLICATION_NOT_ALLOWED);
        else if (contextData == null)
            throw new IllegalStateException("The confirmation is required option and cannot be missing!");
        else if (!contextData.hasKey(JKT))
            throw new IllegalArgumentException("The thumbprint is required option and cannot be missing!");
        else if (!contextData.isType(JKT, DataType.STRING))
            throw new IllegalArgumentException("The JWK Thumbprint within the confirmation object must be a string!");
        else if (!Helpers.equals(contextData.getString(JKT), session.getThumbprint(), false))
            throw new IllegalStateException("The access token thumbprint does not match the session thumbprint.");
        else
            return update(context, data, json);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<AccessObjectData> update(@Nonnull ChannelHandlerContext context,
                                                               @Nonnull AccessContextData contextData,
                                                               @Nonnull AccessObjectData data)
    {
        GlobalAccessManagerImpl manager = context.channel().attr(GlobalAccessManagerImpl.IDENTIFIER).get();
        String rawUniqueId = data.getOptionData().getName();
        if (Helpers.isEmpty(rawUniqueId) || !MiscUtil.isUUID(rawUniqueId))
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        return manager.hasAccess(UUID.fromString(rawUniqueId), data).map(hasAccess ->
        {
            if (hasAccess)
                return createObjectData(manager, contextData, data, manager.getCurrentOrder());
            else
                throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        });
    }

    @Nonnull
    private AccessObjectData createObjectData(@Nonnull GlobalAccessManagerImpl manager,
                                              @Nonnull AccessContextData contextData, @Nonnull AccessObjectData data,
                                              @Nonnull AccessEntryManagerImpl.AccessEntrySnapshot snapshot)
    {
        String uniqueId = UUIDv7.randomUUID().toString();
        String issuer = api.getJNT().getIdentifierString();
        String subject = data.getSubject();
        return EntityBuilder.createObjectData(uniqueId, issuer, subject, manager, contextData, ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS, snapshot);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData data)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), data.getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
