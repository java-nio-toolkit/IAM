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
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Method;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.cookie.ReceivedCookie;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.api.utils.responsebody.JacksonResponseBody;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicResponseReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
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
import com.github.reganjohn.iam.api.requests.restactions.applications.interactions.ApplicationInteractionCreateAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.interactions.ApplicationContextInteractionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundInvoker;
import io.netty.channel.ChannelPipeline;
import io.netty.util.internal.SocketUtils;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
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
        super(api, Routes.Applications.CREATE_APPLICATION_INTERACTION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new InteractionResponseException(InteractionResponse.INVALID_REQUEST);
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
            handleErrorResponse(context, request, raw, errors);
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
        else if (!MiscUtil.isURL(raw.getString("uri"), false))
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
        else if (raw.hasKey("hash_method") && !hasMode(raw.getString("hash_method")))
            throw createParsingException(getModes());
    }

    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull DataObject raw,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (errors.isEmpty())
            handleInternally(context, request, raw);
        else if (errors.stream().allMatch(this::containsLocation))
            throw new InteractionResponseException(InteractionResponse.INVALID_FLAG);
        else
            throw new InteractionResponseException(InteractionResponse.INVALID_REQUEST);
    }

    private boolean containsLocation(@Nonnull InvalidResponseException.SchemaError error)
    {
        return Helpers.equals(error.getLocation(), "flags", true);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject raw)
    {
        ProofObjectData proof = retrieveSelfProof(context);
        String thumbprint = retrieveThumbprint(proof);
        checkClientKey(raw.getObject("client"), proof, thumbprint);
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID ownerId = UUID.fromString(params.get("user_id"));
        UUID applicationId = UUID.fromString(params.get("application_id"));
        long permissions = PermissionUtil.toRaw(raw.getObject("access_token").getArray("access"));
        String label = raw.getObject("access_token").getString("label", null);
        DataObject finish = raw.getObject("interact").getObject("finish");
        api.retrieveUserById(ownerId)
                .flatMap(user -> user.retrieveApplicationById(applicationId))
                .queue(application -> handleApplication(context, proof, thumbprint, application, ownerId, permissions, label, finish), failure -> handleInteractionException(context, failure));
    }

    private void checkClientKey(@Nonnull DataObject client, @Nonnull ProofObjectData data, @Nonnull String thumbprint)
    {
        if (!client.hasKey("key"))
            return;
        else if (!client.isType("key", DataType.OBJECT))
            throw new InteractionResponseException(InteractionResponse.INVALID_CLIENT);
        DataObject key = client.getObject("key");
        if (!"dpop".equals(key.getString("proof", null)) || !key.isType("jwk", DataType.OBJECT)
                || !hasModified(thumbprint, retrieveThumbprint(data, key.getObject("jwk"))))
            throw new InteractionResponseException(InteractionResponse.INVALID_CLIENT);
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
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT));
        else
            context.fireExceptionCaught(failure);
    }

    private void handleApplication(@Nonnull ChannelHandlerContext context, @Nonnull ProofObjectData data,
                                   @Nonnull String thumbprint,
                                   @Nonnull Application application, @Nonnull UUID ownerId,
                                   long permissions, @Nullable String label, @Nonnull DataObject finish)
    {
        if (!Helpers.contains(application.getRedirectUris(), finish.getString("uri"), false))
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_REQUEST));
        else
            checkClient(context, data, application,
                    () -> handleClient(context, thumbprint, application, ownerId, permissions, label, finish));
    }

    public void checkClient(@Nonnull ChannelHandlerContext context, @Nonnull ProofObjectData data,
                            @Nonnull Application application, @Nonnull Runnable handler)
    {
        URI uri = URI.create(application.getOrigin());
        int port = uri.getPort() == -1 ? 443 : uri.getPort();
        InetAddress address = resolveAddress(uri.getHost());
        if (address == null)
            context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT));
        else
            connect(context, data, address, port, handler);
    }

    private void connect(@Nonnull ChannelHandlerContext context, @Nonnull ProofObjectData data,
                         @Nonnull InetAddress address, int port, @Nonnull Runnable handler)
    {
        api.getSocketManager().connect(new InetSocketAddress(address, port)).addListener((ChannelFutureListener) connect ->
        {
            if (connect.isSuccess())
                handleConnect(connect.channel().pipeline(), context, data, handler);
            else
                context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT));
        });
    }

    @Nullable
    private InetAddress resolveAddress(@Nullable String host)
    {
        try
        {
            InetAddress address = SocketUtils.addressByName(host);
            return MiscUtil.isUnsafeAddress(address) ? null : address;
        }
        catch (UnknownHostException ex)
        {
            return null;
        }
    }

    private void handleConnect(@Nonnull ChannelPipeline pipeline, @Nonnull ChannelHandlerContext context,
                               @Nonnull ProofObjectData data, @Nonnull Runnable handler)
    {
        ClassicResponseReceiveHandlerImpl receiver = pipeline.get(ClassicResponseReceiveHandlerImpl.class);
        if (receiver != null)
            pipeline.replace(receiver, null, new ClassicResponseReceiveHandlerImpl(1 << 10, MAX_ACCESS_LENGTH));
        pipeline.addLast(new ApplicationInteractionActionImpl(context, data, handler));
    }

    private void handleClient(@Nonnull ChannelHandlerContext context, @Nonnull String thumbprint,
                              @Nonnull Application application, @Nonnull UUID ownerId,
                              long permissions, @Nullable String label, @Nonnull DataObject finish)
    {
        String token = randomToken();
        ApplicationContextInteraction interaction = createContextInteraction(application, ownerId, permissions, label, finish, thumbprint, token);
        createInteraction(interaction).queue(success -> handleSuccess(context, interaction, token), context::fireExceptionCaught);
    }

    @Nonnull
    private ApplicationContextInteraction createContextInteraction(@Nonnull Application application,
                                                                   @Nonnull UUID ownerId, long permissions,
                                                                   @Nullable String label,
                                                                   @Nonnull DataObject finish,
                                                                   @Nonnull String thumbprint,
                                                                   @Nonnull String continueToken)
    {
        UUID applicationId = application.getUniqueId();
        UUID interactionId = UUIDv7.randomUUID().toUUID();
        String hashMethod = finish.getString("hash_method", DEFAULT_HASH_METHOD);
        OffsetDateTime expires = OffsetDateTime.now().plusSeconds(EXPIRES_IN);
        return new ApplicationContextInteractionImpl(api, ownerId, applicationId, interactionId, expires, permissions,
                finish.getString("uri"), finish.getString("nonce"), randomToken(), hashMethod,
                retrieveUri(ownerId, applicationId), digest(continueToken), thumbprint, label);
    }

    @Nonnull
    private String retrieveUri(@Nonnull UUID ownerId, @Nonnull UUID applicationId)
    {
        return api.getBaseUri() + Routes.Applications.CREATE_APPLICATION_INTERACTION.compile(ownerId.toString(), applicationId.toString()).getCompiledRoute();
    }

    @Nonnull
    private String retrieveThumbprint(@Nonnull ProofObjectData data)
    {
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            return contextData.digest();
        }
        catch (Exception ex)
        {
            throw new InteractionResponseException(InteractionResponse.INVALID_CLIENT);
        }
    }

    @Nonnull
    private String retrieveThumbprint(@Nonnull ProofObjectData data, @Nonnull DataObject jwk)
    {
        try
        {
            SignType type = SignType.from(jwk.getString("alg", data.getEntryData().getMode().getName()));
            AccessEntryData entry = EntityBuilder.createAccessEntry(jwk.getString("kid", null), type, jwk);
            try (AccessContextData contextData = entry.getContext(AccessContextType.SHA_256))
            {
                return contextData.digest();
            }
        }
        catch (Exception ex)
        {
            throw new InteractionResponseException(InteractionResponse.INVALID_CLIENT);
        }
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
                .put("client_thumbprint", interaction.getThumbprint())
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
        Route.CompiledRoute compile = Routes.Applications.ACCEPT_APPLICATION_INTERACTION.compile(owner, application, id);
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
                .put("uri", api.getBaseUri() + Routes.Applications.EXECUTE_APPLICATION_INTERACTION.compile(application, id).getCompiledRoute())
                .put("access_token", DataObject.empty().put("value", continueToken))
                .toData();
    }

    private static class ApplicationInteractionActionImpl extends RestActionImpl
    {
        private static final Route BASE_ROUTE = new Route(Method.GET, ".well-known/jwks.json", true);

        private final ChannelHandlerContext context;
        private final ProofObjectData data;
        private final Runnable handler;

        private ScheduledFuture<?> deadline;
        private boolean finished;

        public ApplicationInteractionActionImpl(@Nonnull ChannelHandlerContext context, @Nonnull ProofObjectData data,
                                                @Nonnull Runnable handler)
        {
            super(BASE_ROUTE);
            this.context = context;
            this.data = data;
            this.handler = handler;
        }

        @Override
        public void handlerAdded(@Nonnull ChannelHandlerContext context)
        {
            this.deadline = context.executor().schedule(() -> onTimeout(context), RETRIEVE_ACCESS_TIMEOUT, TimeUnit.SECONDS);
            CaseInsensitiveMap<String, Collection<String>> headers = new CaseInsensitiveMap<>();
            headers.put("Forwarded", Collections.singletonList("proto=http"));
            List<ReceivedCookie> cookies = Collections.emptyList();
            context.writeAndFlush(new Request(context, this, route.compile(), headers, null, cookies));
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
            if (array.contains(this.data.getEntryData()))
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
            onFailure(context);
            super.channelInactive(context);
        }

        @Override
        public void exceptionCaught(@Nonnull ChannelHandlerContext context,
                                    @Nonnull Throwable failException) throws Exception
        {
            if (finished)
                super.exceptionCaught(context, failException);
            else
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
                handler.run();
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
                this.context.fireExceptionCaught(new InteractionResponseException(InteractionResponse.INVALID_CLIENT));
            }
        }
    }
}
