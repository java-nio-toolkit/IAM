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

package com.github.reganjohn.iam.internal.requests.restactions.applications.interactions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.exceptions.MissingAccessException;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.managers.ProofObjectManager;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.AccessContextInteraction;
import com.github.reganjohn.iam.api.interactions.ApplicationCallbackResponse;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.interactions.ApplicationInteractionRetrieveAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.*;

public class ApplicationInteractionRetrieveActionImpl extends AbstractApplicationActionImpl implements ApplicationInteractionRetrieveAction
{
    public static final MediaType MEDIA_TYPE_ACCESS = MediaType.parse("application/dpop+jwt");

    public ApplicationInteractionRetrieveActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.EXECUTE_APPLICATION_INTERACTION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleApplicationId(context, request, new ArrayList<>());
    }

    private void handleApplicationId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkApplicationId(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("application_id", ex, errors);
        }
        finally
        {
            handleInteractionId(context, request, errors);
        }
    }

    private void checkApplicationId(@Nonnull Map<String, String> params)
    {
        String id = params.get("application_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"application_id\" value is not uuid.");
    }

    private void handleInteractionId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkInteractionId(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("interaction_id", ex, errors);
        }
        finally
        {
            handleErrorResponse(context, request, errors);
        }
    }

    private void checkInteractionId(@Nonnull Map<String, String> params)
    {
        String id = params.get("interaction_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"interaction_id\" value is not uuid.");
    }

    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID applicationId = UUID.fromString(params.get("application_id"));
        UUID interactionId = UUID.fromString(params.get("interaction_id"));
        hasAccess(context, applicationId).queue(hasAccess ->
        {
            if (hasAccess)
                handleInternally(context, applicationId, interactionId);
            else
                throw new MissingAccessException(api.getJNT().getIdentifierString(), ProofObjectManager.INSUFFICIENT_SCOPE);
        }, context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<List<AccessContextInteraction>> retrieveAccess(@Nonnull UUID applicationId)
    {
        Checks.notNull(applicationId, "Application ID");
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM integrations.public_keys WHERE application_id = ?", Collections.singletonList(applicationId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<AccessContextInteraction>> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    interaction.onSuccess(getIAM().getEntityBuilder().createApplicationAccess(array));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SIGNER));
            }
        };
    }

    @Nonnull
    private InteractionCallbackAction<List<AccessEntryData>> retrieveAccessData(@Nonnull UUID applicationId)
    {
        Checks.notNull(applicationId, "Application ID");
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM integrations.public_keys WHERE application_id = ?", Collections.singletonList(applicationId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<AccessEntryData>> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (!array.isEmpty())
                    interaction.onSuccess(getIAM().getEntityBuilder().createAccessEntries(array));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SIGNER));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Boolean> hasAccess(@Nonnull ChannelHandlerContext context,
                                                         @Nonnull UUID applicationId) throws Exception
    {
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        if (data != null)
            return checkAccess(data, applicationId);
        else
            throw new ErrorResponseException(ErrorResponse.MISSING_ACCESS);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Boolean> checkAccess(@Nonnull ProofObjectData data,
                                                           @Nonnull UUID applicationId) throws Exception
    {
        try (AccessContextData context = data.getContext(AccessContextType.SHA_256))
        {
            return retrieveAccess(applicationId).map(set ->
            {
                return set.stream().anyMatch(interaction ->
                {
                    return Helpers.equals(interaction.getThumbprint(), context.digest(), false);
                });
            });
        }
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull UUID applicationId,
                                  @Nonnull UUID interactionId)
    {
        retrieveCallbackResponse(applicationId, interactionId)
                .flatMap(ApplicationCallbackResponse::retrieveApplication)
                .flatMap(application -> retrieveCallbackResponse(application.getUniqueId(), interactionId))
                .flatMap(ApplicationCallbackResponse::delete)
                .flatMap(response -> retrieveAccessData(context, response))
                .queue(interaction -> handleSuccess(context, interaction), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<List<AccessObjectData>> retrieveAccessData(@Nonnull ChannelHandlerContext context,
                                                                                 @Nonnull ApplicationCallbackResponse response)
    {
        return retrieveAccessData(response.getApplicationId()).map(data ->
        {
            return createAccessObjects(context, data, response);
        });
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<ApplicationCallbackResponse> retrieveCallbackResponse(@Nonnull UUID applicationId,
                                                                                            @Nonnull UUID interactionId)
    {
        Checks.notNull(interactionId, "Interaction ID");
        Checks.notNull(applicationId, "Application ID");
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM integrations.responses WHERE application_id = ? AND interaction_id = ?", Arrays.asList(applicationId, interactionId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<ApplicationCallbackResponse> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    interaction.onSuccess(getIAM().getEntityBuilder().createContextResponse(array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
            }
        };
    }

    @Nonnull
    private List<AccessObjectData> createAccessObjects(@Nonnull ChannelHandlerContext context,
                                                       @Nonnull List<AccessEntryData> data,
                                                       @Nonnull ApplicationCallbackResponse response)
    {
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        List<AccessObjectData> set = new ArrayList<>();
        for (AccessEntryData access : data)
            set.add(createAccessObject(manager, access, response));
        return set;
    }

    @Nonnull
    private AccessObjectData createAccessObject(@Nonnull AccessEntryManager manager, @Nonnull AccessEntryData data,
                                                @Nonnull ApplicationCallbackResponse response)
    {
        try (AccessContextData context = data.getContext(AccessContextType.SHA_256))
        {
            AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();
            String uniqueId = UUIDv7.randomUUID().toString();
            String identifier = api.getJNT().getIdentifierString();
            String userId = response.getUserId().toString();
            UUID applicationId = response.getApplicationId();
            DataArray perm = PermissionUtil.toDataArray(response.getPermissions());
            String mediaTypeAccess = ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS;
            return EntityBuilder.createObjectData(uniqueId, identifier, userId, applicationId, perm, manager, context, mediaTypeAccess, snapshot);
        }
        catch (final Exception ex)
        {
            throw new IllegalStateException("Failed to retrieve the snapshot hash", ex);
        }
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull List<AccessObjectData> data)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), data.get(0).getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
