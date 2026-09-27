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
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionCreateEvent;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.interactions.ApplicationInteractionCreateAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.interactions.ApplicationContextInteractionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.*;

public class ApplicationInteractionCreateActionImpl extends AbstractApplicationActionImpl implements ApplicationInteractionCreateAction
{
    public ApplicationInteractionCreateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.CREATE_APPLICATION_INTERACTION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleUniqueId(context, request, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleUniqueId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull DataObject rawData,
                                @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueId(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("application_id", ex, errors);
        }
        finally
        {
            handlePermissions(context, request, rawData, errors);
        }
    }

    private void checkUniqueId(@Nonnull Map<String, String> params)
    {
        String id = params.get("application_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"application_id\" value is not uuid.");
    }

    private void handlePermissions(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject rawData,
                                   @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkPermissions(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("permissions", ex, errors);
        }
        finally
        {
            handleRedirectUri(context, request, rawData, errors);
        }
    }

    private void checkPermissions(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey("permissions"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!rawData.isType("permissions", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"permissions\" is not number.");
    }

    private void handleRedirectUri(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject rawData,
                                   @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkRedirectUri(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("redirect_uri", ex, errors);
        }
        finally
        {
            handleErrorResponse(context, request, rawData, errors);
        }
    }

    private void checkRedirectUri(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey("redirect_uri"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!rawData.isType("redirect_uri", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "Value \"redirect_uri\" is not string.");
        else if (!MiscUtil.isURL(rawData.getString("redirect_uri"), false))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"redirect_uri\" is not url.");
    }

    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull DataObject rawBody,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (errors.isEmpty())
            handleInternally(context, request, rawBody);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody)
    {
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID userId = UUID.fromString(data.getSubject());
        UUID applicationId = UUID.fromString(params.get("application_id"));
        UUID interactionId = UUIDv7.randomUUID().toUUID();
        long permissions = rawBody.getLong("permissions");
        String uri = rawBody.getString("redirect_uri");
        OffsetDateTime expires = OffsetDateTime.now().plusSeconds(300);
        handleInternally(context, new ApplicationContextInteractionImpl(api, userId, applicationId, interactionId, expires, permissions, uri));
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context,
                                  @Nonnull ApplicationContextInteraction interaction)
    {
        api.retrieveUserById(interaction.getOwnerId())
                .flatMap(user -> user.retrieveApplicationById(interaction.getApplicationId()))
                .flatMap(application -> create(application, interaction))
                .queue(success -> handleSuccess(context, interaction), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> create(@Nonnull Application application,
                                                   @Nonnull ApplicationContextInteraction interaction)
    {
        if (Helpers.contains(application.getRedirectUris(), interaction.getRedirectUri(), false))
            return createInteraction(interaction);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_REDIRECT_URI);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> createInteraction(@Nonnull ApplicationContextInteraction interaction)
    {
        Checks.notNull(interaction, "Interaction");
        InteractionMapping mapping = mapFromData(interaction);
        return new InteractionMappingActionImpl<>(api.getJCA(), ClassLoader.getResourceAsString("create_interaction_application.cql"), mapping);
    }

    @Nonnull
    private InteractionMapping mapFromData(@Nonnull ApplicationContextInteraction interaction)
    {
        return new InteractionMapping.Builder()
                .put("user_id", interaction.getOwnerId())
                .put("application_id", interaction.getApplicationId())
                .put("interaction_id", interaction.getUniqueId())
                .put("permissions", interaction.getPermissionsRaw())
                .put("redirect_uri", interaction.getRedirectUri())
                .put("expiry", interaction.getTimeExpiresAt())
                .build();
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context,
                              @Nonnull ApplicationContextInteraction interaction)
    {
        String uri = getRouteCompile(interaction).getCompiledRoute();
        Map<String, String> headers = Collections.singletonMap("Location", uri);
        context.writeAndFlush(new Response(context, StatusReason.CREATED, new ArrayListValuedHashMap<>(headers)))
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
        context.fireUserEventTriggered(new InteractionCreateEvent(interaction));
    }

    @Nonnull
    private Route.CompiledRoute getRouteCompile(@Nonnull ApplicationContextInteraction interaction)
    {
        Checks.notNull(interaction, "Interaction");
        return getRouteCompile(interaction.getApplicationId().toString(), interaction.getUniqueId().toString());
    }

    @Nonnull
    private Route.CompiledRoute getRouteCompile(@Nonnull String applicationId, @Nonnull String interactionId)
    {
        return Routes.Applications.ACCEPT_APPLICATION_INTERACTION.compile(applicationId, interactionId);
    }
}
