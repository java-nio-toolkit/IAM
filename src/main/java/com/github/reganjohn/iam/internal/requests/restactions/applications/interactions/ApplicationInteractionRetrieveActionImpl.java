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
import com.github.adamorgan.jnt.api.requests.*;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.cookie.ReceivedCookie;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.api.utils.responsebody.JacksonResponseBody;
import com.github.adamorgan.jnt.api.utils.responsebody.ResponseBody;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.JNTLogger;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
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
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.slf4j.Logger;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.*;


public class ApplicationInteractionRetrieveActionImpl extends AbstractApplicationActionImpl implements ApplicationInteractionRetrieveAction
{
    public static final Logger LOG = JNTLogger.getLog(ApplicationInteractionRetrieveActionImpl.class);

    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

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
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID applicationId = UUID.fromString(params.get("application_id"));
        UUID interactionId = UUID.fromString(params.get("interaction_id"));
        ProofObjectData data = retrieveSelfProof(context);
        retrieveCallbackResponse(applicationId, interactionId).queue(response -> handleInternally(context, data, response), context::fireExceptionCaught);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull ProofObjectData data,
                                  @Nonnull ApplicationCallbackResponse response)
    {
        response.retrieveApplication().queue(application ->
        {
            URI uri = URI.create(application.getOrigin());
            String host = uri.getHost();
            int port = uri.getPort() == -1 ? 443 : uri.getPort();
            retrieveAccess(context, new InetSocketAddress(host, port), data, response);
        }, context::fireExceptionCaught);
    }

    private void retrieveAccess(@Nonnull ChannelHandlerContext context, @Nonnull InetSocketAddress origin,
                                @Nonnull ProofObjectData data, @Nonnull ApplicationCallbackResponse response)
    {
        api.getSocketManager().connect(origin).addListener((ChannelFutureListener) successObj ->
        {
            if (successObj.isSuccess())
                handleSuccess(successObj, context, data, response);
            else
                handleFailure(context, successObj.cause());
        });
    }

    private void handleSuccess(@Nonnull ChannelFuture connect, @Nonnull ChannelHandlerContext context,
                               @Nonnull ProofObjectData data, @Nonnull ApplicationCallbackResponse response)
    {
        connect.channel().pipeline().addLast(new ApplicationInteractionActionImpl(context, data, response));
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull Throwable cause)
    {
        context.fireExceptionCaught(cause);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Map<AccessEntryData, AccessObjectData>> retrieveAccessData(
            @Nonnull ChannelHandlerContext context,
            @Nonnull ApplicationCallbackResponse response)
    {
        return api.retrieveUserById(response.getUserId())
                .flatMap(User::retrieveAccess)
                .map(data -> createAccessObjects(context, data, response));
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
    private Map<AccessEntryData, AccessObjectData> createAccessObjects(@Nonnull ChannelHandlerContext context,
                                                                       @Nonnull AccessEntryArray data,
                                                                       @Nonnull ApplicationCallbackResponse response)
    {
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        Map<AccessEntryData, AccessObjectData> set = new HashMap<>();
        for (AccessEntryData access : data)
            set.put(access, createAccessObject(manager, access, response));
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
            String type = ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS;
            String userId = response.getUserId().toString();
            UUID applicationId = response.getApplicationId();
            DataArray perm = PermissionUtil.toDataArray(response.getPermissions());
            return EntityBuilder.createObjectData(uniqueId, identifier, userId, applicationId, perm, manager, context, type, snapshot);
        }
        catch (final Exception ex)
        {
            throw new IllegalStateException("Failed to retrieve the snapshot hash", ex);
        }
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataArray successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }

    @Nonnull
    public DataArray fromJSON(@Nonnull Map<AccessEntryData, AccessObjectData> data)
    {
        return data.entrySet().stream().map(this::fromJSON).collect(Helpers.toDataArray());
    }

    @Nonnull
    public DataObject fromJSON(@Nonnull Map.Entry<AccessEntryData, AccessObjectData> data)
    {
        return fromJSON(data.getKey(), data.getValue());
    }

    @Nonnull
    public DataObject fromJSON(@Nonnull AccessEntryData key, @Nonnull AccessObjectData data)
    {
        return DataObject.empty()
                .put("label", key.getUniqueId())
                .put("value", data.getRaw())
                .put("access", data.getScope())
                .toData();
    }

    private static final Route BASE_ROUTE = new Route(Method.GET, ".well-known/jwks.json", true);

    private class ApplicationInteractionActionImpl extends RestActionImpl
    {
        private final ChannelHandlerContext context;
        private final ProofObjectData data;
        private final ApplicationCallbackResponse response;

        public ApplicationInteractionActionImpl(@Nonnull ChannelHandlerContext context, @Nonnull ProofObjectData data,
                                                @Nonnull ApplicationCallbackResponse response)
        {
            super(BASE_ROUTE);
            this.context = context;
            this.data = data;
            this.response = response;
        }

        @Override
        public void handlerAdded(@Nonnull ChannelHandlerContext context)
        {
            LOG.debug("Sending interaction request on route {}", route.getRoute());
            Route.CompiledRoute route = this.route.compile();
            CaseInsensitiveMap<String, Collection<String>> headers = new CaseInsensitiveMap<>();
            headers.put("Forwarded", Collections.singletonList("proto=http"));
            List<ReceivedCookie> cookies = Collections.emptyList();
            context.writeAndFlush(new Request(context, this, route, headers, null, cookies));
        }

        @Override
        public void handleResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull Response response) throws Exception
        {
            if (response.isError())
                handleFailure(context, new InvalidResponseException(response.code, response.message));
            else if (response.code >= 300 && response.code < 400)
                reject(context);
            else
                handleResponse(context, response, response.getBody());
        }

        private void handleResponse(@Nonnull ChannelHandlerContext context, @Nonnull Response response, ResponseBody body) throws Exception
        {
            LOG.debug("The interaction request was successfully finished with status {}", response.code);
            if (!(body instanceof JacksonResponseBody) || !((JacksonResponseBody) body).isObject())
                fail(context);
            else
                handleResponse((JacksonResponseBody) body);
        }

        private void handleResponse(@Nonnull JacksonResponseBody body) throws Exception
        {
            AccessEntryArray array = EntityBuilder.createAccessEntryArray(body.getObject());
            if (array.contains(this.data.getEntryData()))
                handleSuccess();
            else
                context.fireExceptionCaught(new MissingAccessException(api.getJNT().getIdentifierString(), ProofObjectManager.INSUFFICIENT_SCOPE));
        }

        private void handleSuccess()
        {
            this.response.delete()
                    .flatMap(response -> retrieveAccessData(context, response))
                    .map(ApplicationInteractionRetrieveActionImpl.this::fromJSON)
                    .queue(array -> ApplicationInteractionRetrieveActionImpl.this.handleSuccess(context, array), context::fireExceptionCaught);
        }

        private void reject(@Nonnull ChannelHandlerContext context)
        {
            LOG.warn("The interaction requests do not allow the use of redirects.");
            fail(context);
        }

        private void fail(@Nonnull ChannelHandlerContext connection)
        {
            this.context.fireExceptionCaught(new ErrorResponseException(ErrorResponse.SERVER_ERROR));
            connection.close();
        }

        @Override
        public void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull InvalidResponseException ex)
        {
            LOG.warn("The interaction request finished with an fail", ex);
            fail(context);
        }
    }
}
