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

import com.github.adamorgan.jnt.api.handle.classic.ClassicObjectHandler;
import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataPath;
import com.github.adamorgan.jnt.api.utils.cookie.ReceivedCookie;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.api.utils.responsebody.JacksonResponseBody;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicResponseReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.AccessEntryActionImpl;
import com.github.adamorgan.jnt.internal.utils.CallbackContext;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionCreateEvent;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.interactions.ApplicationInteractionCreateAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.interactions.ApplicationContextInteractionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.github.reganjohn.iam.internal.utils.ApplicationUtil;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundInvoker;
import io.netty.channel.ChannelPipeline;
import io.netty.util.concurrent.FutureListener;
import com.github.adamorgan.jnt.api.utils.collection.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class ApplicationInteractionCreateActionImpl extends AbstractApplicationActionImpl implements ApplicationInteractionCreateAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public ApplicationInteractionCreateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Interactions.CREATE_APPLICATION_INTERACTION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new InteractionResponseException(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY);
        else
            handleOwnerId(context, request, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleOwnerId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull DataObject raw,
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
            handleUniqueId(context, request, raw, errors);
        }
    }

    private void handleUniqueId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull DataObject raw,
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
            handleAccessToken(context, request, raw, errors);
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

    private void handleAccessToken(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject raw,
                                   @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkAccessToken(raw);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("access_token", ex, errors);
        }
        finally
        {
            handleFlags(context, request, raw, errors);
        }
    }

    private void checkAccessToken(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("access_token"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("access_token", DataType.OBJECT))
            throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
        else
            handleAccess(raw.getObject("access_token"));
    }

    private void handleAccess(DataObject raw)
    {
        if (!raw.hasKey("access"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("access", DataType.ARRAY))
            throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
        else if (raw.getArray("access").isEmpty())
            throw new DataObjectParsingException(BASE_TYPE_MIN_LENGTH, "The \"access\" value may not be empty.");
        else if (!PermissionUtil.isValid(raw.getArray("access")))
            throw createParsingException(PermissionUtil.getNames());
        else if (raw.hasKey("label") && !raw.isType("label", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"label\" value is not string.");
    }

    private void handleFlags(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                             @Nonnull DataObject raw,
                             @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkFlags(raw);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("flags", ex, errors);
        }
        finally
        {
            handleClient(context, request, raw, errors);
        }
    }

    private void checkFlags(@Nonnull DataObject raw)
    {
        if (!raw.isType("access_token", DataType.OBJECT) || !raw.getObject("access_token").hasKey("flags"))
            return;
        else
            checkToken(raw.getObject("access_token"));
    }

    private void checkToken(@Nonnull DataObject token)
    {
        if (!token.isType("flags", DataType.ARRAY) || !token.getArray("flags").isEmpty())
            throw createParsingException(Collections.emptyList());
    }

    private void handleClient(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject raw,
                              @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkClient(raw);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("client", ex, errors);
        }
        finally
        {
            handleStart(context, request, raw, errors);
        }
    }

    private void checkClient(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("client"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("client", DataType.OBJECT))
            throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
        else
            checkKey(raw.getObject("client"));
    }

    private void checkKey(@Nonnull DataObject client)
    {
        if (!client.hasKey("key"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!client.isType("key", DataType.OBJECT))
            throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
        else
            checkProof(client.getObject("key"));
    }

    private void checkProof(@Nonnull DataObject key)
    {
        if (!key.hasKey("proof"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!key.isType("proof", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"proof\" value is not string.");
        else if (!key.getString("proof").equals("httpsig"))
            throw createParsingException(Collections.singletonList("httpsig"));
        else if (!key.hasKey("jwk"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!key.isType("jwk", DataType.OBJECT))
            throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
    }

    private void handleStart(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                             @Nonnull DataObject raw,
                             @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkStart(raw);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("interact.start", ex, errors);
        }
        finally
        {
            handleFinish(context, request, raw, errors);
        }
    }

    private void checkStart(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("interact"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("interact", DataType.OBJECT))
            throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
        else
            checkInteract(raw.getObject("interact"));
    }

    private void checkInteract(@Nonnull DataObject interact)
    {
        if (!interact.hasKey("start"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!interact.isType("start", DataType.ARRAY))
            throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
        else if (!interact.getArray("start").has("redirect", DataType.STRING))
            throw createParsingException(Collections.singletonList("redirect"));
    }

    private void handleFinish(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject raw,
                              @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkBody(raw);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("interact.finish", ex, errors);
        }
        finally
        {
            checkAccess(context, request, raw, errors);
        }
    }

    private void checkBody(@Nonnull DataObject raw)
    {
        if (!raw.isType("interact", DataType.OBJECT))
            return;
        else
            checkInteractionRaw(raw.getObject("interact"));
    }

    private void checkInteractionRaw(DataObject raw)
    {
        if (!raw.hasKey("finish"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("finish", DataType.OBJECT))
            throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
        else
            checkFinish(raw.getObject("finish"));
    }

    private void checkFinish(DataObject raw)
    {
        if (!raw.hasKey("method"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("method", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"method\" value is not string.");
        else if (!raw.getString("method").equals("redirect"))
            throw createParsingException(Collections.singletonList("redirect"));
        else if (!raw.hasKey("uri"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("uri", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"uri\" value is not string.");
        else if (!isRedirectUri(raw.getString("uri")))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"uri\" is not url.");
        else if (!raw.hasKey("nonce"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("nonce", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"nonce\" value is not string.");
        else if (raw.isEmpty("nonce"))
            throw new DataObjectParsingException(STRING_TYPE_MIN, "The \"nonce\" value may not be empty.");
        else if (raw.getString("nonce").length() < MIN_NONCE_LENGTH || raw.getString("nonce").length() > MAX_NONCE_LENGTH)
            throw new DataObjectParsingException(BASE_TYPE_BAD_LENGTH, Helpers.format("The \"nonce\" value must be between %d and %d characters long.", MIN_NONCE_LENGTH, MAX_NONCE_LENGTH));
        else if (raw.hasKey("hash_method") && !raw.isType("hash_method", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"hash_method\" value is not string.");
        else if (raw.hasKey("hash_method") && !ApplicationUtil.MODES.containsKey(raw.getString("hash_method")))
            throw createParsingException(ApplicationUtil.MODES.keySet());
    }

    private void checkAccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request, @Nonnull DataObject raw,
                             @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (errors.isEmpty())
            handleAccess(context, request, raw);
        else if (errors.stream().allMatch(this::containsLocation))
            throw new InteractionResponseException(InteractionResponse.INVALID_FLAG, ErrorResponse.INVALID_FORM_BODY);
        else
            throw new InteractionResponseException(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY);
    }

    private void handleAccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request, @Nonnull DataObject raw)
    {
        DataObject rawAccess = DataPath.getObject(raw, "client.key.jwk");
        AccessEntryData access = api.getAccessSignatureManager().verify(context, request, rawAccess);
        handleInternally(context, request, access, raw);
    }

    private boolean containsLocation(@Nonnull InvalidResponseException.SchemaError error)
    {
        return Helpers.equals(error.getLocation(), "flags", true);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull AccessEntryData access, @Nonnull DataObject raw)
    {
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID ownerId = UUID.fromString(params.get("user_id"));
        UUID applicationId = UUID.fromString(params.get("application_id"));
        long permissions = PermissionUtil.toRaw(raw.getObject("access_token").getArray("access"));
        String label = raw.getObject("access_token").getString("label", null);
        DataObject finish = raw.getObject("interact").getObject("finish");
        api.retrieveUserById(ownerId)
                .flatMap(user -> user.retrieveApplicationById(applicationId))
                .queue(application -> handleApplication(context, access, access.toData(), application, ownerId, permissions, label, finish), failure -> handleInteractionException(context, failure));
    }

    private void handleInteractionException(@Nonnull ChannelHandlerContext context, @Nonnull Throwable failure)
    {
        if (!(failure instanceof ErrorResponseException))
            context.fireExceptionCaught(failure);
        else
            handleErrorResponse(context, (ErrorResponseException) failure);
    }

    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull ErrorResponseException failure)
    {
        int code = failure.getErrorCode();
        if (code == ErrorResponse.UNKNOWN_USER.getCode() || code == ErrorResponse.UNKNOWN_APPLICATION.getCode())
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.UNKNOWN_APPLICATION));
        else
            context.fireExceptionCaught(failure);
    }

    private void handleApplication(@Nonnull ChannelHandlerContext context, @Nonnull AccessEntryData data,
                                   @Nonnull DataObject rawAccess,
                                   @Nonnull Application application, @Nonnull UUID ownerId,
                                   long permissions, @Nullable String label, @Nonnull DataObject finish)
    {
        if (!Helpers.contains(application.getRedirectUris(), finish.getString("uri"), false))
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY));
        else
            checkClient(context, data, rawAccess, application, ownerId, permissions, label, finish);
    }

    public void checkClient(@Nonnull ChannelHandlerContext context, @Nonnull AccessEntryData data,
                            @Nonnull DataObject rawAccess, @Nonnull Application application, @Nonnull UUID ownerId,
                            long permissions, @Nullable String label, @Nonnull DataObject finish)
    {
        URI uri = URI.create(application.getOrigin());
        if (uri.getHost() == null)
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.UNKNOWN_ACCESS));
        else
            resolve(context, data, rawAccess, application, ownerId, uri, permissions, label, finish);
    }

    private void resolve(@Nonnull ChannelHandlerContext context, @Nonnull AccessEntryData data,
                         @Nonnull DataObject rawAccess, @Nonnull Application application, @Nonnull UUID ownerId,
                         @Nonnull URI uri, long permissions, @Nullable String label, @Nonnull DataObject finish)
    {
        MiscUtil.resolveSafeAddress(api.getJDT(), uri.getHost()).addListener((FutureListener<InetAddress>) future ->
        {
            InetAddress address = future.getNow();
            if (address == null)
                context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.UNKNOWN_ACCESS));
            else
                connect(context, data, rawAccess, application, ownerId, permissions, label, finish, address, uri);
        });
    }

    private void connect(@Nonnull ChannelHandlerContext context, @Nonnull AccessEntryData data,
                         @Nonnull DataObject rawAccess, @Nonnull Application application, @Nonnull UUID ownerId,
                         long permissions, @Nullable String label, @Nonnull DataObject finish,
                         @Nonnull InetAddress address, URI uri)
    {
        int port = uri.getPort() == -1 ? 443 : uri.getPort();
        api.getSocketManager().connect(new InetSocketAddress(address, port)).addListener((ChannelFutureListener) connect ->
        {
            if (connect.isSuccess())
                handleConnect(connect.channel().pipeline(), context, data, rawAccess, application, ownerId, permissions, label, finish);
            else
                context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.UNKNOWN_ACCESS));
        });
    }

    private void handleConnect(@Nonnull ChannelPipeline pipeline, @Nonnull ChannelHandlerContext context,
                               @Nonnull AccessEntryData data, @Nonnull DataObject rawAccess,
                               @Nonnull Application application, @Nonnull UUID ownerId,
                               long permissions, @Nullable String label, @Nonnull DataObject finish)
    {
        ClassicResponseReceiveHandlerImpl receiver = pipeline.get(ClassicResponseReceiveHandlerImpl.class);
        if (receiver != null)
            pipeline.replace(receiver, null, new ClassicResponseReceiveHandlerImpl(new ClassicObjectHandler.Builder().setMaxBufferSize(MAX_ACCESS_LENGTH).build()));
        pipeline.addLast(new ApplicationInteractionActionImpl(context, data, rawAccess, application, ownerId, permissions, label, finish));
    }

    public void handleClient(@Nonnull ChannelHandlerContext context, @Nonnull DataObject access,
                             @Nonnull Application application, @Nonnull UUID ownerId,
                             long permissions, @Nullable String label, @Nonnull DataObject finish)
    {
        String token = ApplicationUtil.randomToken();
        ApplicationContextInteraction interaction = createContextInteraction(application, ownerId, permissions, label, finish, access, token);
        createInteraction(interaction).queue(success -> handleSuccess(context, interaction, token), context::fireExceptionCaught);
    }

    @Nonnull
    private ApplicationContextInteraction createContextInteraction(@Nonnull Application application,
                                                                   @Nonnull UUID ownerId, long permissions,
                                                                   @Nullable String label,
                                                                   @Nonnull DataObject finish,
                                                                   @Nonnull DataObject access,
                                                                   @Nonnull String continueToken)
    {
        UUID applicationId = application.getUniqueId();
        UUID interactionId = UUIDv7.randomUUID().toUUID();
        String hashMethod = finish.getString("hash_method", ApplicationUtil.DEFAULT_HASH_METHOD);
        OffsetDateTime expires = OffsetDateTime.now().plusSeconds(EXPIRES_IN);
        return new ApplicationContextInteractionImpl(api, ownerId, applicationId, interactionId, expires, permissions,
                finish.getString("uri"), finish.getString("nonce"), ApplicationUtil.randomToken(), hashMethod,
                retrieveUri(ownerId, applicationId), ApplicationUtil.digest(continueToken), access, label);
    }

    @Nonnull
    private String retrieveUri(@Nonnull UUID ownerId, @Nonnull UUID applicationId)
    {
        return api.getBaseUri() + Routes.Interactions.CREATE_APPLICATION_INTERACTION.compile(ownerId.toString(), applicationId.toString()).getCompiledRoute();
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> createInteraction(@Nonnull ApplicationContextInteraction interaction)
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
                .put("nonce", interaction.getClientNonce())
                .put("finish", interaction.getFinishNonce())
                .put("method_hash", interaction.getMethodHash())
                .put("uri", interaction.getUri())
                .put("hash", interaction.hash())
                .put("access_raw", interaction.getAccessRaw().toString())
                .put("label", interaction.getLabel())
                .build();
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context,
                              @Nonnull ApplicationContextInteraction interaction, @Nonnull String continueToken)
    {
        DataObject json = fromData(interaction, continueToken);
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, json.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body))
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
    private DataObject fromData(@Nonnull ApplicationContextInteraction interaction,
                                @Nonnull String continueToken)
    {
        return DataObject.empty()
                .put("interact", fromInteract(interaction))
                .put("continue", fromContinue(interaction, continueToken))
                .toData();
    }

    @Nonnull
    private DataObject fromInteract(@Nonnull ApplicationContextInteraction interaction)
    {
        String owner = interaction.getOwnerId().toString();
        String application = interaction.getApplicationId().toString();
        String id = interaction.getUniqueId().toString();
        Route.CompiledRoute compile = Routes.Interactions.ACCEPT_APPLICATION_INTERACTION.compile(owner, application, id);
        return DataObject.empty()
                .put("redirect", api.getBaseUri() + compile.getCompiledRoute())
                .put("finish", interaction.getFinishNonce())
                .put("expires_in", EXPIRES_IN)
                .toData();
    }

    @Nonnull
    private DataObject fromContinue(@Nonnull ApplicationContextInteraction interaction,
                                    @Nonnull String continueToken)
    {
        String application = interaction.getApplicationId().toString();
        String id = interaction.getUniqueId().toString();
        return DataObject.empty()
                .put("uri", api.getBaseUri() + Routes.Interactions.EXECUTE_APPLICATION_INTERACTION.compile(application, id).getCompiledRoute())
                .put("access_token", DataObject.empty().put("value", continueToken))
                .toData();
    }

    private class ApplicationInteractionActionImpl extends AccessEntryActionImpl
    {
        private final ChannelHandlerContext context;
        private final AccessEntryData data;
        private final DataObject rawAccess;
        private final Application application;
        private final UUID ownerId;
        private final long permissions;
        private final String label;
        private final DataObject finish;

        private ScheduledFuture<?> deadline;
        private boolean finished;

        public ApplicationInteractionActionImpl(@Nonnull ChannelHandlerContext context, @Nonnull AccessEntryData data,
                                                @Nonnull DataObject rawAccess, @Nonnull Application application,
                                                @Nonnull UUID ownerId, long permissions, @Nullable String label,
                                                @Nonnull DataObject finish)
        {
            this.context = context;
            this.data = data;
            this.rawAccess = rawAccess;
            this.application = application;
            this.ownerId = ownerId;
            this.permissions = permissions;
            this.label = label;
            this.finish = finish;
        }

        @Override
        public void handlerAdded(@Nonnull ChannelHandlerContext context)
        {
            this.deadline = context.executor().schedule(() -> onTimeout(context), RETRIEVE_ACCESS_TIMEOUT, TimeUnit.SECONDS);
            List<ReceivedCookie> cookies = Collections.emptyList();
            context.writeAndFlush(new Request(context, this, route.compile(), new CaseInsensitiveMap<>(), null, cookies));
        }

        @Override
        public void handleResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull Response response) throws Exception
        {
            if (response.isError() || (response.code >= 300 && response.code < 400))
                onFailure(context);
            else if (!(response.getBody() instanceof JacksonResponseBody) || !((JacksonResponseBody) response.getBody()).isObject())
                onFailure(context);
            else
                handleInternally(context, (JacksonResponseBody) response.getBody());
        }

        private void handleInternally(@Nonnull ChannelHandlerContext context,
                                      @Nonnull JacksonResponseBody body) throws Exception
        {
            AccessEntryArray array = EntityBuilder.createAccessEntryArray(body.getObject());
            if (array.contains(this.data))
                closeResource(context);
            else
                onFailure(context);
        }

        @Override
        public void handlerRemoved(@Nonnull ChannelHandlerContext context)
        {
            deadline.cancel(false);
        }

        @Override
        public void channelInactive(@Nonnull ChannelHandlerContext context) throws Exception
        {
            try (CallbackContext<ChannelHandlerContext> resource = new CallbackContext<>(context, super::channelInactive))
            {
                onFailure(context);
            }
        }

        @Override
        public void exceptionCaught(@Nonnull ChannelHandlerContext context, @Nonnull Throwable ex) throws Exception
        {
            onFailure(context);
        }

        private void onTimeout(@Nonnull ChannelHandlerContext context)
        {
            try
            {
                onFailure(context);
            }
            catch (Exception ex)
            {
                context.fireExceptionCaught(ex);
            }
        }

        private void closeResource(ChannelHandlerContext context) throws Exception
        {
            finished = true;
            try (CallbackContext<ChannelHandlerContext> resource = new CallbackContext<>(context, ChannelOutboundInvoker::close))
            {
                handleClient(this.context, rawAccess, application, ownerId, permissions, label, finish);
            }
        }

        @Override
        public void handleFailure(@Nonnull ChannelHandlerContext context,
                                  @Nonnull InvalidResponseException ex) throws Exception
        {
            onFailure(context);
        }

        private void onFailure(@Nonnull ChannelHandlerContext context) throws Exception
        {
            if (finished)
                return;
            finished = true;
            try (CallbackContext<ChannelHandlerContext> resource = new CallbackContext<>(context, ChannelOutboundInvoker::close))
            {
                this.context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.UNKNOWN_ACCESS));
            }
        }
    }
}
