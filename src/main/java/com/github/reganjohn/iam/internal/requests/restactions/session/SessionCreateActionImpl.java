/*
 * Copyright 2026 Ada Morgan, John Regan and the JNT contributors
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

package com.github.reganjohn.iam.internal.requests.restactions.session;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
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
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.requestbody.RequestBody;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.requests.restactions.session.SessionCreateAction;
import com.github.reganjohn.iam.api.utils.sessions.SessionCreateData;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static com.github.reganjohn.iam.api.requests.restactions.UserAction.*;

public class SessionCreateActionImpl extends AbstractSessionActionImpl implements SessionCreateAction
{
    private static final Map<String, List<String>> signTypes = new ConcurrentHashMap<>();

    static
    {
        for (SignType signType : SignType.values())
        {
            if (signType.getType() == AccessEntryType.NONE)
                continue;
            List<String> set = signTypes.computeIfAbsent(signType.getType().name(), __ -> new ArrayList<>());
            set.add(signType.getName());
        }
    }

    public static final MediaType MEDIA_TYPE_ACCESS = MediaType.parse("application/dpop+jwt");

    private static final String ASSERT_TYPE = ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS;

    public SessionCreateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.ADD_SESSION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        RequestBody body = request.getBody();
        if (!(body instanceof JacksonRequestBody && ((JacksonRequestBody) body).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleBody(context, request, ((JacksonRequestBody) body).getObject(), new ArrayList<>());
    }

    private void handleBody(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                            @Nonnull DataObject rawBody, @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkObject(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.KEY, ex, schemaErrors);
        }
        finally
        {
            handleRawBody(context, request, rawBody, schemaErrors);
        }
    }

    private void handleRawBody(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull DataObject rawBody, @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        DataObject rawData = rawBody.getObject(ProofObjectManager.KEY, DataObject.empty());
        if (Helpers.nonEmpty(schemaErrors))
            handleInternally(context, request, rawBody, schemaErrors);
        else if (rawData == null)
            throw createErrorResponse(ProofObjectManager.KEY, BASE_TYPE_REQUIRED, "This field is required.");
        else
            handleKeyword(context, request, rawBody, rawData, schemaErrors);
    }

    private void checkObject(@Nonnull DataObject rawBody)
    {
        if (!rawBody.hasKey(ProofObjectManager.KEY))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawBody.isType(ProofObjectManager.KEY, DataType.OBJECT))
            throw new DataObjectParsingException(DICT_TYPE_CONVERT, "Only dictionaries may be used in a DictType.");
    }

    private void handleKeyword(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
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
            handleCanManage(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void checkKeyword(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.KTY))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.KTY, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.KTY));
        else if (!signTypes.containsKey(rawData.getString(ProofObjectManager.KTY)))
            throw createParsingException(ProofObjectManager.KTY, signTypes.keySet());
    }

    private void handleCanManage(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
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
            handleAccess(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void handleAccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        if (Helpers.isEmpty(schemaErrors))
            handleAccessEntry(context, request, rawBody, rawData, schemaErrors);
        else
            handleInternally(context, request, rawBody, schemaErrors);
    }

    private void checkCanManage(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.USE))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.USE, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.USE));
        else if (!Helpers.equals(rawData.getString(ProofObjectManager.USE), "sig", true))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value must be sig.");
    }

    private void handleAccessEntry(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                                   @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        AccessEntryType type = AccessEntryType.valueOf(rawData.getString(ProofObjectManager.KTY));
        if (type == AccessEntryType.OKP || type == AccessEntryType.EC)
            handleExtension(context, request, rawBody, rawData, schemaErrors);
        else
            handleUniqueId(context, request, rawBody, rawData, schemaErrors);
    }

    private void handleExtension(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkExtension(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.CRV, ex, schemaErrors);
        }
        finally
        {
            handleCanAccess(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void checkExtension(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.CRV))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.CRV, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.CRV));
    }

    private void handleCanAccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkCanAccess(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.KTY, ex, schemaErrors);
        }
        finally
        {
            handleUniqueId(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void checkCanAccess(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.CRV))
            return;
        else if (!rawData.hasKey(ProofObjectManager.CRV, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.CRV));
        else if (!Helpers.contains(signTypes.keySet(), rawData.getString(ProofObjectManager.KTY), true))
            throw createParsingException(ProofObjectManager.CRV, signTypes.keySet());
    }

    private void handleUniqueId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
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
            handleAvailable(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void checkUniqueId(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.KID))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.KID, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.KID));
    }

    private void handleAvailable(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
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
            handleFields(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void checkAvailable(@Nonnull DataObject rawData)
    {
        String type = rawData.getString(ProofObjectManager.KTY);
        if (!rawData.hasKey(ProofObjectManager.ALG))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.ALG, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.ALG));
        else if (!Helpers.contains(signTypes.get(type), rawData.getString(ProofObjectManager.ALG), true))
            throw createParsingException(ProofObjectManager.ALG, signTypes.get(type));
    }

    private void handleFields(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        AccessEntryType type = AccessEntryType.valueOf(rawData.getString(ProofObjectManager.KTY));
        for (String key : getFields(type))
            handleField(context, rawData, key, schemaErrors);
        handleAlgorithm(context, request, rawBody, rawData, schemaErrors);
    }

    private void handleField(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawData,
                             @Nonnull String key, @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
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
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", key));
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
                                 @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
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
            handleCurve(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void checkAlgorithm(@Nonnull DataObject rawData)
    {
        SignType signType = SignType.from(rawData.getString(ProofObjectManager.ALG));
        String type = rawData.getString(ProofObjectManager.KTY);
        if (!Helpers.equals(signType.getType(), type, true))
            throw createParsingException(ProofObjectManager.ALG, signType);
    }

    private void handleCurve(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                             @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
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
            handleInternally(context, request, rawBody, schemaErrors);
        }
    }

    private void checkCurve(@Nonnull DataObject rawData)
    {
        SignType signType = SignType.from(rawData.getString(ProofObjectManager.ALG));
        String type = rawData.getString(ProofObjectManager.KTY);
        String crv = rawData.getString(ProofObjectManager.CRV);
        if (!Helpers.equals(signType.getType(), type, true))
            return;
        else if (signType.hasExtension() && !Helpers.equals(crv, signType.getRawName(), true))
            throw createParsingException(ProofObjectManager.CRV, signType);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody, @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(50035, "Invalid Form Body", errors);
        DataObject rawData = rawBody.getObject(ProofObjectManager.KEY);
        AccessObjectData objectData = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();
        AccessEntryData entryData = AbstractEntityBuilder.createAccessEntry(rawData);
        try (AccessContextData contextData = entryData.getContext(AccessContextType.SHA_256))
        {
            String uniqueId = UUIDv7.randomUUID().toString();
            String issuer = api.getJNT().getIdentifierString();
            String subject = objectData.getSubject();
            AccessOptionData optionData = new AccessOptionData(snapshot.getName(), ASSERT_TYPE, manager.getSignType());
            AccessObjectData json = EntityBuilder.createObjectData(uniqueId, issuer, subject, manager, contextData, optionData, snapshot);
            onSessionCreate(context, request, entryData, contextData, json);
        }
    }

    private void onSessionCreate(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull AccessEntryData entryData, @Nonnull AccessContextData contextData,
                                 @Nonnull AccessObjectData objectData)
    {
        UUIDv7 sessionId = UUIDv7.nameUUIDFromBytes(entryData.getPublicKey().getEncoded());
        String subject = objectData.getSubject();
        String userAgent = request.getHeaders().get(USER_AGENT);
        String thumbprint = contextData.digest();
        UUID userId = UUID.fromString(subject);
        SessionCreateData session = new SessionCreateData(userId, sessionId.toUUID(), userAgent, entryData, 0, thumbprint);
        api.retrieveSessionCount(userId)
                .queue(count ->
                {
                    if (count == 0)
                        throw new ErrorResponseException(ErrorResponse.UNKNOWN_USER);
                    else if (count <= MAX_SESSION_COUNT)
                        handle(context, session, objectData);
                    else
                        throw new ErrorResponseException(ErrorResponse.MAX_SESSIONS);
                }, context::fireExceptionCaught);
    }

    private void handle(@Nonnull ChannelHandlerContext context, @Nonnull SessionCreateData session,
                        @Nonnull AccessObjectData objectData)
    {
        api.createSession(session)
                
                .queue(success -> handleSuccess(context, objectData), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData objectData)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), objectData.getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
