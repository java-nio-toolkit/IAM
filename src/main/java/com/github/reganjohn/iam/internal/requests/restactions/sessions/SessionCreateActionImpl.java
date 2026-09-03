/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.internal.requests.restactions.sessions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.managers.ProofObjectManager;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.sessions.SessionCreateAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.api.utils.sessions.SessionCreateData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractSessionActionImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.*;

public class SessionCreateActionImpl extends AbstractSessionActionImpl implements SessionCreateAction
{
    public static final MediaType MEDIA_TYPE_ACCESS = MediaType.parse("application/dpop+jwt");

    public SessionCreateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.ADD_SESSION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleKeyword(context, request, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleKeyword(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull DataObject rawData,
                               @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkKeyword(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.KTY, ex, schemaErrors);
        }
        finally
        {
            handleCanManage(context, request, rawData, schemaErrors);
        }
    }

    private void checkKeyword(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.KTY))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.KTY, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, Helpers.format("Value \"%s\" is not string.", ProofObjectManager.KTY));
        else if (!Helpers.contains(IAMImpl.signTypes.keySet(), rawData.getString(ProofObjectManager.KTY), true))
            throw createParsingException(ProofObjectManager.KTY, IAMImpl.signTypes.keySet());
    }

    private void handleCanManage(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkCanManage(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.USE, ex, schemaErrors);
        }
        finally
        {
            handleAccess(context, request, rawData, schemaErrors);
        }
    }

    private void handleAccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        if (Helpers.isEmpty(schemaErrors))
            handleAccessEntry(context, request, rawData, schemaErrors);
        else
            handleInternally(context, request, rawData, schemaErrors);
    }

    private void checkCanManage(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.USE))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.USE, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, Helpers.format("Value \"%s\" is not string.", ProofObjectManager.USE));
        else if (!Helpers.equals(rawData.getString(ProofObjectManager.USE), "sig", true))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value must be sig.");
    }

    private void handleAccessEntry(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject rawData,
                                   @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        AccessEntryType type = AccessEntryType.valueOf(rawData.getString(ProofObjectManager.KTY).toUpperCase(Locale.ROOT));
        if (type == AccessEntryType.OKP || type == AccessEntryType.EC)
            handleCanAccess(context, request, rawData, schemaErrors);
        else
            handleUniqueId(context, request, rawData, schemaErrors);
    }

    private void handleCanAccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkCanAccess(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.CRV, ex, schemaErrors);
        }
        finally
        {
            handleUniqueId(context, request, rawData, schemaErrors);
        }
    }

    private void checkCanAccess(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.CRV))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.CRV, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, Helpers.format("Value \"%s\" is not string.", ProofObjectManager.CRV));
        else if (!canAccess(rawData.getString(ProofObjectManager.KTY), rawData.getString(ProofObjectManager.CRV)))
            throw createParsingException(ProofObjectManager.CRV, IAMImpl.signTypes.get(rawData.getString(ProofObjectManager.KTY)));
    }

    private boolean canAccess(String type, String crv)
    {
        return Helpers.contains(IAMImpl.signTypes.get(type), crv, true);
    }

    private void handleUniqueId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull DataObject rawData,
                                @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueId(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.KID, ex, schemaErrors);
        }
        finally
        {
            handleAvailable(context, request, rawData, schemaErrors);
        }
    }

    private void checkUniqueId(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.KID))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.KID, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, Helpers.format("Value \"%s\" is not string.", ProofObjectManager.KID));
    }

    private void handleAvailable(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkAvailable(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.ALG, ex, schemaErrors);
        }
        finally
        {
            handleFields(context, request, rawData, schemaErrors);
        }
    }

    private void checkAvailable(@Nonnull DataObject rawData)
    {
        String type = rawData.getString(ProofObjectManager.KTY);
        if (!rawData.hasKey(ProofObjectManager.ALG))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.ALG, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, Helpers.format("Value \"%s\" is not string.", ProofObjectManager.ALG));
        else if (!Helpers.contains(IAMImpl.signTypes.get(type), rawData.getString(ProofObjectManager.ALG), true))
            throw createParsingException(ProofObjectManager.ALG, IAMImpl.signTypes.get(type));
    }

    private void handleFields(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        AccessEntryType type = AccessEntryType.valueOf(rawData.getString(ProofObjectManager.KTY).toUpperCase(Locale.ROOT));
        for (String key : getFields(type))
            handleField(context, rawData, key, schemaErrors);
        handleAlgorithm(context, request, rawData, schemaErrors);
    }

    private void handleField(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawData, @Nonnull String key,
                             @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkField(key, rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(key, ex, schemaErrors);
        }
    }

    private void checkField(@Nonnull String key, @Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(key))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.isType(key, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, Helpers.format("Value \"%s\" is not string.", key));
    }

    @Nonnull
    private List<String> getFields(@Nonnull AccessEntryType type)
    {
        switch (type)
        {
            case RSA:
                return Helpers.listOf("n", "e");
            case EC:
                return Helpers.listOf("x", "y");
            case OKP:
                return Helpers.listOf("x");
            default:
                return Collections.emptyList();
        }
    }

    private void handleAlgorithm(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkAlgorithm(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.ALG, ex, schemaErrors);
        }
        finally
        {
            handleCurve(context, request, rawData, schemaErrors);
        }
    }

    private void checkAlgorithm(@Nonnull DataObject rawData)
    {
        SignType signType = SignType.from(rawData.getString(ProofObjectManager.ALG));
        String type = rawData.getString(ProofObjectManager.KTY);
        if (signType == SignType.NONE || signType == SignType.UNKNOWN)
            throw createParsingException(ProofObjectManager.ALG, IAMImpl.signTypes.get(type));
        else if (!Helpers.equals(signType.getType(), type, true))
            throw createParsingException(ProofObjectManager.ALG, signType);
    }

    private void handleCurve(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                             @Nonnull DataObject rawData,
                             @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkCurve(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.CRV, ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, request, rawData, schemaErrors);
        }
    }

    private void checkCurve(@Nonnull DataObject rawData)
    {
        SignType signType = SignType.from(rawData.getString(ProofObjectManager.ALG));
        String rawType = rawData.getString(ProofObjectManager.KTY);
        AccessEntryType type = AccessEntryType.valueOf(rawType);
        if (type == AccessEntryType.RSA)
            return;
        String crv = rawData.getString(ProofObjectManager.CRV);
        if (signType == SignType.NONE || signType == SignType.UNKNOWN)
            throw createParsingException(ProofObjectManager.CRV, IAMImpl.signTypes.get(rawType));
        else if (signType.hasExtension() && !Helpers.equals(crv, signType.getRawName(), true))
            throw createParsingException(ProofObjectManager.CRV, signType);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();
        AccessEntryData entryData = AbstractEntityBuilder.createAccessEntry(rawBody);
        try (AccessContextData contextData = entryData.getContext(AccessContextType.SHA_256))
        {
            String uniqueId = UUIDv7.randomUUID().toString();
            String issuer = api.getJNT().getIdentifierString();
            String subject = data.getSubject();
            AccessObjectData json = EntityBuilder.createObjectData(uniqueId, issuer, subject, manager, contextData, ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS, snapshot);
            SessionCreateData rawData = fromData(request, entryData, contextData, json);
            handleInternally(context, json, rawData);
        }
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData data,
                                  @Nonnull SessionCreateData session)
    {
        api.retrieveUserById(session.getUserId())
                .flatMap(User::retrieveSessionCount)
                .flatMap(count -> create(session, count))
                .queue(success -> handleSuccess(context, data), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private SessionCreateData fromData(@Nonnull Request request, @Nonnull AccessEntryData entryData,
                                       @Nonnull AccessContextData context, @Nonnull AccessObjectData data)
    {
        UUIDv7 sessionId = UUIDv7.nameUUIDFromBytes(entryData.getPublic().getEncoded());
        String subject = data.getSubject();
        String userAgent = request.getHeaders().get("User-Agent");
        String thumbprint = context.digest();
        UUID userId = UUID.fromString(subject);
        return new SessionCreateData(userId, sessionId.toUUID(), userAgent, entryData, 0, thumbprint);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> create(SessionCreateData session, int count)
    {
        if (count == 0)
            throw new ErrorResponseException(ErrorResponse.UNKNOWN_USER);
        else if (count > MAX_SESSION_COUNT)
            throw new ErrorResponseException(ErrorResponse.MAX_SESSIONS);
        else
            return create(session);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> create(@Nonnull SessionCreateData session)
    {
        Checks.notNull(session, "Session");
        return new InteractionMappingActionImpl<>(api.getJCA(), ClassLoader.getResourceAsString("create_session.cql"), session)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.ACCESS_ALREADY_EXISTS));
            }
        };
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData data)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), data.getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.CREATED, new CaseInsensitiveMap<>(), body));
    }
}
