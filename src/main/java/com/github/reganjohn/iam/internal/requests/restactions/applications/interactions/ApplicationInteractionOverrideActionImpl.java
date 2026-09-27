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
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.Query;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionOverrideEvent;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.interactions.ApplicationInteractionOverrideAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.requests.objaction.InteractionListType;
import com.reganjohn.c4j.internal.requests.objaction.InteractionListContextActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.*;

public class ApplicationInteractionOverrideActionImpl extends AbstractApplicationActionImpl implements ApplicationInteractionOverrideAction
{
    public ApplicationInteractionOverrideActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.ACCEPT_APPLICATION_INTERACTION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleApplicationId(context, request, new ArrayList<>());
    }

    private void handleApplicationId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
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
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
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
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (errors.isEmpty())
            handleInternally(context, request);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID applicationId = UUID.fromString(params.get("application_id"));
        UUID interactionId = UUID.fromString(params.get("interaction_id"));
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        api.retrieveUserById(UUID.fromString(json.getSubject()))
                .flatMap(user -> user.retrieveApplicationById(applicationId))
                .flatMap(application -> application.retrieveInteractionById(interactionId))
                .flatMap(interaction -> createResponse(json, interaction))
                .queue(interaction -> handleSuccess(context, interaction), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context,
                               @Nonnull ApplicationContextInteraction interaction)
    {
        CaseInsensitiveMap<String, List<String>> headers = new CaseInsensitiveMap<>();
        headers.put("Location", new ArrayList<>(List.of(withQueryParam(interaction))));
        context.writeAndFlush(new Response(context, StatusReason.SEE_OTHER, headers))
                .addListener(successObj ->
                {
                    if (successObj.isSuccess())
                        onEvent(context, interaction);
                    else
                        context.fireExceptionCaught(successObj.cause());
                });
    }

    private void onEvent(@Nonnull ChannelHandlerContext context, @Nonnull ApplicationContextInteraction interaction)
    {
        context.fireUserEventTriggered(new InteractionOverrideEvent(interaction));
    }

    @Nonnull
    private String withQueryParam(@Nonnull ApplicationContextInteraction interaction)
    {
        Checks.notNull(interaction, "Interaction");
        return new Query(interaction.getRedirectUri())
                .withQueryParam("application_id", interaction.getApplicationId())
                .withQueryParam("interaction_id", interaction.getUniqueId())
                .toString();
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<ApplicationContextInteraction> createResponse(@Nonnull AccessObjectData json,
                                                                                   @Nonnull ApplicationContextInteraction interaction)
    {
        UUID ownerId = interaction.getOwnerId();
        UUID applicationId = interaction.getApplicationId();
        UUID interactionId = interaction.getUniqueId();
        UUID userId = UUID.fromString(json.getSubject());
        long permissions = interaction.getPermissionsRaw();
        return new InteractionListContextActionImpl<>(api.getJCA(), InteractionListType.LOGGED, new ArrayListValuedHashMap<>())
                .add("DELETE FROM integrations.interactions WHERE user_id = ? AND application_id = ? AND interaction_id = ?", userId, applicationId, interactionId)
                .add(ClassLoader.getResourceAsString("create_interaction_response.cql"), interactionId, userId, ownerId, applicationId, permissions)
                .add(ClassLoader.getResourceAsString("create_entitlement.cql"), userId, applicationId, ownerId, 0L, permissions, OffsetDateTime.now())
                .map(unused -> interaction);
    }
}
