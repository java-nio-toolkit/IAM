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

package com.github.reganjohn.iam.test.restaction.sessions;

import com.github.adamorgan.jnt.api.exceptions.InvalidTokenException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.managers.GlobalAccessManagerImpl;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.SessionUpdateActionImpl;
import com.github.reganjohn.iam.test.assertions.restaction.RestActionAssertions;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import java.util.UUID;
import java.util.stream.Stream;

import static com.github.adamorgan.jnt.api.managers.ProofObjectManager.JKT;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SessionUpdateActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID SESSION_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final String TOKEN = "access.token.value";
    private static final String THUMBPRINT = "session-thumbprint";

    private SessionUpdateActionImpl newAction()
    {
        return new SessionUpdateActionImpl(api);
    }

    private static String hashOf(String token)
    {
        return IOUtil.encodeURL(DigestUtils.sha256(token));
    }

    private void withAccessProof(String thumbprint, String tokenHash)
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(thumbprint);
        ProofObjectData proof = mock(ProofObjectData.class);
        when(proof.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        when(proof.getAccessTokenHash()).thenReturn(tokenHash);
        channel.attr(ProofObjectManagerImpl.CONTEXT).set(proof);
    }

    private void withManager(boolean hasAccess)
    {
        InteractionCallbackAction<Boolean> access = completed(hasAccess);
        GlobalAccessManagerImpl manager = mock(GlobalAccessManagerImpl.class);
        when(manager.hasAccess(any())).thenReturn(access);
        when(manager.getCurrentOrder()).thenReturn(mock(AccessEntryManagerImpl.AccessEntrySnapshot.class));
        channel.attr(GlobalAccessManagerImpl.IDENTIFIER).set(manager);
    }

    private static AccessObjectData accessObject(String subject, DataObject confirmation, DataObject actor)
    {
        AccessObjectData access = mock(AccessObjectData.class);
        when(access.getThumbprint()).thenReturn("proof-thumbprint");
        when(access.getSubject()).thenReturn(subject);
        when(access.getContextData()).thenReturn(confirmation);
        when(access.getActor()).thenReturn(actor);
        return access;
    }

    private static AccessObjectData accessObject()
    {
        return accessObject(USER_ID.toString(), DataObject.empty().put(JKT, THUMBPRINT), null);
    }

    private void withStoredSession()
    {
        Session session = withSession(SESSION_ID, USER_ID, "Mozilla/5.0", 0, THUMBPRINT);
        User user = withUser(USER_ID, "alice", null, 0);
        withSession(user, SESSION_ID, completed(session));
        withRetrieval(USER_ID, completed(user));
    }

    private RestActionAssertions assertThatUpdating()
    {
        return assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withHeader("Authorization", "DPoP " + TOKEN);
    }

    private void whenHandled(RestActionAssertions assertions, AccessObjectData access)
    {
        try (MockedStatic<AbstractEntityBuilder> parsed = mockStatic(AbstractEntityBuilder.class);
             MockedStatic<EntityBuilder> issued = mockStatic(EntityBuilder.class))
        {
            parsed.when(() -> AbstractEntityBuilder.createAccessObject(anyString())).thenReturn(access);
            withIssuedObject(issued);

            assertions.whenHandled();
        }
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty", "", "session_id=BASE_TYPE_REQUIRED"),
                arguments("not_uuid", "not-a-uuid", "session_id=UUID_TYPE_COERCE"),
                arguments("too_short", "02b1a26a-f033-7e2f-8ba7", "session_id=UUID_TYPE_COERCE"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", "session_id=UUID_TYPE_COERCE"),
                arguments("without_dashes", "02b1a26af0337e2f8ba7543bd0ac755a", "session_id=UUID_TYPE_COERCE"));
    }

    static Stream<Arguments> testInvalidToken()
    {
        return Stream.of(
                arguments("no_confirmation", null, ErrorResponseException.class),
                arguments("no_thumbprint_claim", DataObject.empty(), ErrorResponseException.class),
                arguments("thumbprint_claim_not_string", DataObject.empty().put(JKT, 5), ErrorResponseException.class),
                arguments("other_session_thumbprint", DataObject.empty().put(JKT, "another-thumbprint"), ErrorResponseException.class));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String sessionId, String errors)
    {
        assertThatRequestTo(newAction())
                .withRouteParams(sessionId)
                .withHeader("Authorization", "DPoP " + TOKEN)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFormErrors(errors.split("[=,]"))
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testValidSession()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        withStoredSession();

        whenHandled(assertThatUpdating()
                .hasStatus(StatusReason.OK.code)
                .hasContentType(SessionUpdateActionImpl.MEDIA_TYPE_ACCESS)
                .hasBodyEqualTo(ISSUED_OBJECT), accessObject());
    }

    @ValueSource(strings = {"", "DPoP", "DPoP first second"})
    @ParameterizedTest
    void testMalformedAuthorization(String authorization)
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withHeader("Authorization", authorization)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testMissingAuthorization()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNAUTHORIZED)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testMissingProof()
    {
        assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ProofAccessException.class)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testProofOfAnotherKey()
    {
        withAccessProof("another-thumbprint", hashOf(TOKEN));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class), accessObject());

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testProofOfAnotherToken()
    {
        withAccessProof("proof-thumbprint", hashOf("another.token"));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class), accessObject());

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testApplicationToken()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        withStoredSession();
        AccessObjectData access = accessObject(USER_ID.toString(), DataObject.empty().put(JKT, THUMBPRINT), DataObject.empty().put("sub", "application"));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.APPLICATION_NOT_ALLOWED), access);
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidToken(String name, DataObject confirmation, Class<? extends Throwable> type)
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        withStoredSession();
        AccessObjectData access = accessObject(USER_ID.toString(), confirmation, null);

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(type), access);
    }

    @Test
    void testDeniedAccess()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(false);
        withStoredSession();

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(InvalidTokenException.class), accessObject());
    }

    @Test
    void testUnknownUser()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_USER), accessObject());
    }

    @Test
    void testUnknownSession()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        User user = withUser(USER_ID, "alice", null, 0);
        withSession(user, SESSION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION)));
        withRetrieval(USER_ID, completed(user));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_SESSION), accessObject());
    }
}
