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

package com.github.reganjohn.iam.internal.requests.restactions.entitlements;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.exceptions.InvalidTokenException;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.entitlements.PermissionOverrideUpdateAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.managers.GlobalAccessManagerImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.concurrent.FastThreadLocal;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.github.adamorgan.jnt.api.managers.ProofObjectManager.JKT;

public class PermissionOverrideUpdateActionImpl extends AbstractApplicationActionImpl implements PermissionOverrideUpdateAction
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

    public PermissionOverrideUpdateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Entitlements.UPDATE_ENTITLEMENT_ACCESS);
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
            handleErrorResponse("application_id", ex, schemaErrors);
        }
        finally
        {
            handleErrorResponse(context, request, schemaErrors);
        }
    }

    private void checkUniqueID(@Nonnull Map<String, String> params)
    {
        String id = params.get("application_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"application_id\" value is not uuid.");
    }

    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (errors.isEmpty())
            handleInternally(context, request);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        String authorization = Helpers.get(request.getHeaders(), "Authorization");
        String[] parts = Helpers.nonEmpty(authorization) ? authorization.split(" ") : new String[0];
        if (parts.length != 2)
            throw new ErrorResponseException(ErrorResponse.UNAUTHORIZED);
        String accessToken = parts[1];
        ProofObjectData data = retrieveSelfProof(context);
        AccessObjectData json = EntityBuilder.createAccessObject(accessToken);
        MessageDigest messageDigest = SHA256.get();
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            byte[] hash = messageDigest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
            if (!Helpers.equals(json.getThumbprint(), contextData.digest(), false))
                throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
            else if (!Helpers.equals(IOUtil.encodeURL(hash), data.getAccessTokenHash(), false))
                throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
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
        UUID applicationId = UUID.fromString(request.getRoute().getMajorParameters().get("application_id"));
        api.retrieveUserById(userId)
                .flatMap(user -> user.retrieveEntitlementById(applicationId))
                .flatMap(permission -> update(context, contextData, json, permission))
                .queue(data -> handleSuccess(context, data), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<AccessObjectData> update(@Nonnull ChannelHandlerContext context,
                                                               @Nonnull AccessContextData data,
                                                               @Nonnull AccessObjectData json,
                                                               @Nonnull PermissionOverride permission)
    {
        return api.retrieveUserById(permission.getUserId())
                .flatMap(User::retrieveAccess)
                .map(this::retrieveThumbprints)
                .flatMap(thumbprints -> update(context, data, json, thumbprints, permission));
    }


    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<AccessObjectData> update(@Nonnull ChannelHandlerContext context,
                                                               @Nonnull AccessContextData data,
                                                               @Nonnull AccessObjectData json,
                                                               @Nonnull List<String> thumbprints,
                                                               @Nonnull PermissionOverride permission)
    {
        DataObject contextData = json.getContextData();
        if (contextData == null)
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        else if (json.getActor() == null)
            throw new ErrorResponseException(ErrorResponse.ONLY_APPLICATION_ALLOWED);
        else if (!json.getActor().hasKey("sub", DataType.STRING))
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        else if (!MiscUtil.isUUID(json.getActor().getString("sub")))
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        else if (!contextData.hasKey(JKT))
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        else if (!contextData.isType(JKT, DataType.STRING))
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        else if (!Helpers.contains(thumbprints, contextData.getString(JKT), false))
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        else
            return update(context, permission, data, json, json.getActor());
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<AccessObjectData> update(@Nonnull ChannelHandlerContext context,
                                                               @Nonnull PermissionOverride permission,
                                                               @Nonnull AccessContextData contextData,
                                                               @Nonnull AccessObjectData data,
                                                               @Nonnull DataObject actor)
    {
        GlobalAccessManagerImpl manager = (GlobalAccessManagerImpl) context.channel().attr(GlobalAccessManagerImpl.IDENTIFIER).get();
        return manager.hasAccess(data).map(hasAccess ->
        {
            if (hasAccess)
                return createObjectData(manager, permission, contextData, data, actor, manager.getCurrentOrder());
            else
                throw new InvalidTokenException();
        });
    }

    @Nonnull
    private AccessObjectData createObjectData(@Nonnull GlobalAccessManagerImpl manager,
                                              @Nonnull PermissionOverride context,
                                              @Nonnull AccessContextData contextData, @Nonnull AccessObjectData data,
                                              @Nonnull DataObject actorData,
                                              @Nonnull AccessEntryManagerImpl.AccessEntrySnapshot snapshot)
    {
        String uniqueId = UUIDv7.randomUUID().toString();
        String issuer = api.getJNT().getIdentifierString();
        UUID actor = UUID.fromString(actorData.getString("sub"));
        DataArray permission = PermissionUtil.toDataArray(context.getPermissions());
        return EntityBuilder.createObjectData(uniqueId, issuer, data.getSubject(), actor, permission, manager, contextData, ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS, snapshot);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData data)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), data.getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }

    @Nonnull
    @Unmodifiable
    private List<String> retrieveThumbprints(@Nonnull AccessEntryArray interactions)
    {
        return interactions.stream().map(this::retrieveThumbprint).collect(Collectors.toUnmodifiableList());
    }

    @Nonnull
    private String retrieveThumbprint(@Nonnull AccessEntryData data)
    {
        try (AccessContextData context = data.getContext(AccessContextType.SHA_256))
        {
            return context.digest();
        }
        catch (Exception ex)
        {
            throw new IllegalStateException("Failed to retrieve the snapshot hash", ex);
        }
    }
}
