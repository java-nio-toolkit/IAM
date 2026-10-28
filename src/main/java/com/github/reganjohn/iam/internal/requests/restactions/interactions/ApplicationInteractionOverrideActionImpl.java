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

package com.github.reganjohn.iam.internal.requests.restactions.interactions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.Query;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionOverrideEvent;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.interactions.ApplicationInteractionOverrideAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import com.github.reganjohn.iam.internal.utils.ApplicationUtil;
import io.netty.channel.ChannelHandlerContext;
import com.github.adamorgan.jnt.api.utils.collection.CaseInsensitiveMap;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.*;

public class ApplicationInteractionOverrideActionImpl extends AbstractApplicationActionImpl implements ApplicationInteractionOverrideAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public ApplicationInteractionOverrideActionImpl(@Nonnull IAMImpl api)
    {
        this(api, Routes.Interactions.ACCEPT_APPLICATION_INTERACTION);
    }

    protected ApplicationInteractionOverrideActionImpl(@Nonnull IAMImpl api, @Nonnull Route route)
    {
        super(api, route);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleOwnerId(context, request, new ArrayList<>());
    }

    private void handleOwnerId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkOwnerId(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("user_id", ex, errors);
        }
        finally
        {
            handleApplicationId(context, request, errors);
        }
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

    protected void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID ownerId = UUID.fromString(params.get("user_id"));
        UUID applicationId = UUID.fromString(params.get("application_id"));
        UUID interactionId = UUID.fromString(params.get("interaction_id"));
        UUID userId = retrieveSelfUserId(context);
        String thumbprint = retrieveThumbprint(retrieveSelfProof(context));
        String token = ApplicationUtil.randomToken();
        api.retrieveUserById(ownerId)
                .flatMap(user -> user.retrieveApplicationById(applicationId))
                .flatMap(application -> application.retrieveInteractionById(interactionId))
                .flatMap(interaction -> createResponse(userId, thumbprint, token, checkRedirectUri(interaction)))
                .queue(interaction -> handleSuccess(context, interaction, token, isJson(request)), context::fireExceptionCaught);
    }

    @Nonnull
    private ApplicationContextInteraction checkRedirectUri(@Nonnull ApplicationContextInteraction interaction)
    {
        if (!interaction.getTimeExpiresAt().isAfter(OffsetDateTime.now()))
            throw new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION);
        else if (!isRedirectUri(interaction.getRedirectUri()))
            throw new ErrorResponseException(ErrorResponse.INVALID_REDIRECT_URI);
        return interaction;
    }

    @Nonnull
    private String retrieveThumbprint(@Nonnull ProofObjectData proof)
    {
        try (AccessContextData contextData = proof.getContext(AccessContextType.SHA_256))
        {
            return contextData.digest();
        }
        catch (Exception ex)
        {
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        }
    }

    private static boolean isJson(@Nonnull Request request)
    {
        String accept = request.getHeaders().getFirst("Accept");
        return accept != null && accept.contains("application/json");
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context,
                               @Nonnull ApplicationContextInteraction interaction, @Nonnull String reference,
                               boolean json)
    {
        String location = withQueryParam(interaction, reference);
        context.writeAndFlush(json ? createJsonResponse(context, location) : createRedirectResponse(context, location))
                .addListener(successObj ->
                {
                    if (successObj.isSuccess())
                        onEvent(context, interaction);
                    else
                        context.fireExceptionCaught(successObj.cause());
                });
    }

    @Nonnull
    private Response createRedirectResponse(@Nonnull ChannelHandlerContext context, @Nonnull String location)
    {
        CaseInsensitiveMap<String, String> headers = new CaseInsensitiveMap<>();
        headers.put("Location", Collections.singletonList(location));
        return new Response(context, StatusReason.SEE_OTHER, headers);
    }

    @Nonnull
    private Response createJsonResponse(@Nonnull ChannelHandlerContext context, @Nonnull String location)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, DataObject.empty().put("redirect_uri", location).toBinary(), true);
        return new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body);
    }

    protected void onEvent(@Nonnull ChannelHandlerContext context, @Nonnull ApplicationContextInteraction interaction)
    {
        context.fireUserEventTriggered(new InteractionOverrideEvent(interaction));
    }

    @Nonnull
    private String withQueryParam(@Nonnull ApplicationContextInteraction interaction, @Nonnull String reference)
    {
        Checks.notNull(interaction, "Interaction");
        String method = interaction.getMethodHash();
        String clientNonce = interaction.getClientNonce();
        String finishNonce = interaction.getFinishNonce();
        String uri = interaction.getUri();
        String hash = ApplicationUtil.hash(method, clientNonce, finishNonce, reference, uri);
        return new Query(interaction.getRedirectUri())
                .withQueryParam("hash", hash)
                .withQueryParam("interact_ref", reference)
                .toString();
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<ApplicationContextInteraction> createResponse(@Nonnull UUID userId,
                                                                                   @Nonnull String thumbprint,
                                                                                   @Nonnull String reference,
                                                                                   @Nonnull ApplicationContextInteraction interaction)
    {
        return createResponse(userId, thumbprint, reference, interaction, false);
    }

    @Nonnull
    @CheckReturnValue
    protected InteractionCallbackAction<ApplicationContextInteraction> createResponse(@Nonnull UUID userId,
                                                                                      @Nonnull String thumbprint,
                                                                                      @Nonnull String reference,
                                                                                      @Nonnull ApplicationContextInteraction interaction,
                                                                                      boolean denied)
    {
        String content = ClassLoader.getResourceAsString(denied ? "deny_interaction.cql" : "accept_interaction.cql");
        Map<String, Object> params = dataFromMap(userId, thumbprint, reference, interaction, denied);
        return new InteractionMappingActionImpl<Map<String, Object>>(api.getJCA(), content, params)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Map<String, Object>> request, @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
                else
                    request.onSuccess(params);
            }
        }.flatMap(consumed -> createResponse(consumed, interaction));
    }

    @Nonnull
    @Unmodifiable
    private Map<String, Object> dataFromMap(@Nonnull UUID userId, @Nonnull String thumbprint, @Nonnull String reference,
                                            @Nonnull ApplicationContextInteraction interaction, boolean denied)
    {
        return new InteractionMapping.Builder()
                .put("interaction_id", interaction.getUniqueId())
                .put("user_id", userId)
                .put("owner_id", interaction.getOwnerId())
                .put("application_id", interaction.getApplicationId())
                .put("permissions", interaction.getPermissionsRaw())
                .put("reference", reference)
                .put("hash", interaction.hash())
                .put("access_raw", interaction.getAccessRaw().toString())
                .put("thumbprint", thumbprint)
                .put("label", interaction.getLabel())
                .put("updated_at", OffsetDateTime.now())
                .put("denied", denied)
                .toMap();
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<ApplicationContextInteraction> createResponse(@Nonnull Map<String, Object> params,
                                                                                    @Nonnull ApplicationContextInteraction interaction)
    {
        return new InteractionMappingActionImpl<ApplicationContextInteraction>(api.getJCA(), ClassLoader.getResourceAsString("create_interaction_response.cql"), params)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<ApplicationContextInteraction> request,
                                      @Nonnull BufferArray array)
            {
                request.onSuccess(interaction);
            }
        };
    }
}
