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

package com.github.reganjohn.iam.internal.requests.restactions.application.interactions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.ApplicationContext;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationCallbackResponse;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.application.interactions.ApplicationInteractionRetrieveAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.application.AbstractApplicationActionImpl;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.*;

import static com.github.reganjohn.iam.api.requests.restactions.UserAction.BASE_TYPE_REQUIRED;
import static com.github.reganjohn.iam.api.requests.restactions.UserAction.UUID_TYPE_COERCE;

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
        if (errors.isEmpty())
            handleInternally(context, request);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID applicationId = UUID.fromString(params.get("application_id"));
        UUID interactionId = UUID.fromString(params.get("interaction_id"));
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            retrieveCallbackResponse(applicationId, interactionId)
                    .flatMap(ApplicationCallbackResponse::retrieveApplication)
                    .flatMap(Application::retrieveAccess)
                    .map(application -> retrieveApplication(application, contextData))
                    .flatMap(application -> retrieveCallbackResponse(application.getUniqueId(), interactionId))
                    .map(response -> createObjectData(context, data, response))
                    .queue(interaction -> handleSuccess(context, interaction));
        }
    }

    @Nonnull
    private Application retrieveApplication(@Nonnull ApplicationContext info, @Nonnull AccessContextData context)
    {
        if (Helpers.contains(info.getThumbprints(), context.digest(), false))
            return info.getApplication();
        else
            throw new ErrorResponseException(ErrorResponse.MISSING_ACCESS);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<ApplicationCallbackResponse> retrieveCallbackResponse(@Nonnull UUID applicationId,
                                                                                            @Nonnull UUID interactionId)
    {
        InteractionMapping map = new InteractionMapping.Builder()
                .put("application_id", applicationId)
                .put("interaction_id", interactionId)
                .build();
        return new InteractionMappingActionImpl<>(api.getJACT(), ClassLoader.getResourceAsString("retrieve_interaction_response.cql"), map)
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
    private AccessObjectData createObjectData(@Nonnull ChannelHandlerContext context, @Nonnull ProofObjectData data,
                                              @Nonnull ApplicationCallbackResponse response)
    {
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            String uniqueId = UUIDv7.randomUUID().toString();
            String identifier = api.getJNT().getIdentifierString();
            UUID userId = response.getUserId();
            UUID applicationId = response.getApplicationId();
            DataArray perm = PermissionUtil.toDataArray(response.getPermissions());
            return EntityBuilder.createObjectData(uniqueId, identifier, userId.toString(), applicationId, perm, manager, contextData, ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS, snapshot);
        }
        catch (Exception ex)
        {
            throw new IllegalStateException(ex);
        }
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData data)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), data.getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
