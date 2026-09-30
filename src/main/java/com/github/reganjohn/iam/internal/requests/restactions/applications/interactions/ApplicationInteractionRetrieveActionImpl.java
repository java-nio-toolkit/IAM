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
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationCallbackResponse;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.interactions.ApplicationInteractionRetrieveAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class ApplicationInteractionRetrieveActionImpl extends AbstractApplicationActionImpl implements ApplicationInteractionRetrieveAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public ApplicationInteractionRetrieveActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.EXECUTE_APPLICATION_INTERACTION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new InteractionResponseException(InteractionResponse.INVALID_REQUEST);
        else
            handleApplicationId(context, request, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleApplicationId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull DataObject raw,
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
            handleInteractionId(context, request, raw, errors);
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
                                     @Nonnull DataObject raw,
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
            handleReference(context, request, raw, errors);
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

    private void handleReference(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject raw,
                                 @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkReference(raw);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("interact_ref", ex, errors);
        }
        finally
        {
            handleErrorResponse(context, request, raw, errors);
        }
    }

    private void checkReference(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("interact_ref"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("interact_ref", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"interact_ref\" value is not string.");
        else if (raw.isEmpty("interact_ref"))
            throw new DataObjectParsingException(STRING_TYPE_MIN, "The \"interact_ref\" value may not be empty.");
    }

    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull DataObject raw,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (errors.isEmpty())
            handleInternally(context, request, raw);
        else
            throw new InteractionResponseException(InteractionResponse.INVALID_REQUEST);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject raw)
    {
        Map<String, String> params = request.getRoute().getMajorParameters();
        String thumbprint = retrieveThumbprint(retrieveSelfProof(context));
        String token = retrieveContinuationToken(request);
        UUID applicationId = UUID.fromString(params.get("application_id"));
        UUID interactionId = UUID.fromString(params.get("interaction_id"));
        retrieveCallbackResponse(applicationId, interactionId)
                .queue(response -> handleResponse(context, thumbprint, token, raw.getString("interact_ref"), response),
                        failure -> context.fireExceptionCaught(toClientError(failure)));
    }

    @Nonnull
    private String retrieveContinuationToken(@Nonnull Request request)
    {
        String authorization = Helpers.get(request.getHeaders(), "Authorization");
        String[] parts = Helpers.nonEmpty(authorization) ? authorization.split(" ") : new String[0];
        if (parts.length != 2 || !parts[0].equalsIgnoreCase("GNAP") || parts[1].isEmpty())
            throw new InteractionResponseException(InteractionResponse.INVALID_CONTINUATION);
        else
            return parts[1];
    }

    @Nonnull
    private Throwable toClientError(@Nonnull Throwable failure)
    {
        if (failure instanceof ErrorResponseException && ((ErrorResponseException) failure).getErrorCode() == ErrorResponse.UNKNOWN_INTERACTION.getCode())
            return new InteractionResponseException(InteractionResponse.INVALID_CONTINUATION);
        else
            return failure;
    }

    private void handleResponse(@Nonnull ChannelHandlerContext context, @Nonnull String thumbprint,
                                @Nonnull String token, @Nonnull String interactRef,
                                @Nonnull ApplicationCallbackResponse response)
    {
        if (!hasModified(thumbprint, response.getClientThumbprint()))
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT));
        else if (!hasModified(digest(token), response.getContinueHash()))
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CONTINUATION));
        else if (!hasModified(interactRef, response.getInteractionReference()))
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_INTERACTION));
        else
            retrieveAccessData(context, response)
                    .flatMap(data -> response.delete().map(deleted -> toData(response, data)))
                    .queue(json -> handleSuccess(context, json), context::fireExceptionCaught);
    }

    @Nonnull
    private DataObject toData(@Nonnull ApplicationCallbackResponse response, @Nonnull AccessObjectData data)
    {
        DataObject raw = DataObject.empty()
                .put("value", data.getRaw())
                .put("access", PermissionUtil.toDataArray(response.getPermissions()))
                .put("key", response.getThumbprint())
                .put("expires_in", Duration.between(data.getTimeCreated(), data.getTimeExpiresAt()).getSeconds())
                .toData();
        if (response.getLabel() != null)
            raw.put("label", response.getLabel());
        return Helpers.singletonData("access_token", raw);
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
            throw new InteractionResponseException(InteractionResponse.INVALID_CLIENT);
        }
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<AccessObjectData> retrieveAccessData(@Nonnull ChannelHandlerContext context,
                                                                           @Nonnull ApplicationCallbackResponse response)
    {
        return api.retrieveUserById(response.getUserId())
                .flatMap(User::retrieveAccess)
                .map(entries -> createAccessObject(context, entries, response));
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<ApplicationCallbackResponse> retrieveCallbackResponse(@Nonnull UUID applicationId,
                                                                                            @Nonnull UUID interactionId)
    {
        Checks.notNull(interactionId, "Interaction ID");
        Checks.notNull(applicationId, "Application ID");
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM integrations.responses WHERE application_id = ? AND interaction_id = ?", Arrays.asList(applicationId, interactionId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
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
    private AccessObjectData createAccessObject(@Nonnull ChannelHandlerContext context, @Nonnull AccessEntryArray entries,
                                                @Nonnull ApplicationCallbackResponse response)
    {
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        for (AccessEntryData entry : entries)
        {
            if (hasThumbprint(entry, response.getThumbprint()))
                return createAccessObject(manager, entry, response);
        }
        throw new InteractionResponseException(InteractionResponse.INVALID_INTERACTION);
    }

    private boolean hasThumbprint(@Nonnull AccessEntryData entry, @Nonnull String thumbprint)
    {
        try (AccessContextData contextData = entry.getContext(AccessContextType.SHA_256))
        {
            return hasModified(contextData.digest(), thumbprint);
        }
        catch (Exception ex)
        {
            throw new IllegalStateException("Failed to retrieve the snapshot hash", ex);
        }
    }

    @Nonnull
    private AccessObjectData createAccessObject(@Nonnull AccessEntryManager manager, @Nonnull AccessEntryData entry,
                                                @Nonnull ApplicationCallbackResponse response)
    {
        try (AccessContextData contextData = entry.getContext(AccessContextType.SHA_256))
        {
            return createAccessObject(manager, contextData, response);
        }
        catch (Exception ex)
        {
            throw new IllegalStateException("Failed to retrieve the snapshot hash", ex);
        }
    }

    @Nonnull
    private AccessObjectData createAccessObject(@Nonnull AccessEntryManager manager, @Nonnull AccessContextData contextData,
                                                @Nonnull ApplicationCallbackResponse response)
    {
        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();
        String uniqueId = UUIDv7.randomUUID().toString();
        String identifier = api.getJNT().getIdentifierString();
        String type = ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS;
        String userId = response.getUserId().toString();
        UUID applicationId = response.getApplicationId();
        DataArray perm = PermissionUtil.toDataArray(response.getPermissions());
        return EntityBuilder.createObjectData(uniqueId, identifier, userId, applicationId, perm, manager, contextData, type, snapshot);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataObject successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
