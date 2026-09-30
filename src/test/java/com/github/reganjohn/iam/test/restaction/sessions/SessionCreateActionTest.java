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

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.restactions.SessionAction;
import com.github.reganjohn.iam.api.utils.sessions.SessionCreateData;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.SessionCreateActionImpl;
import com.github.reganjohn.iam.test.assertions.restaction.RestActionAssertions;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SessionCreateActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final String USER_AGENT = "iam-test/1.0";

    private SessionCreateActionImpl newAction()
    {
        return new SessionCreateActionImpl(api);
    }

    private SessionCreateActionImpl newAction(ArgumentCaptor<SessionCreateData> created)
    {
        SessionCreateActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).create(created.capture());
        return action;
    }

    private void withStoredUser(int count)
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withSessionCount(user, completed(count));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
    }

    private static void whenHandled(RestActionAssertions assertions)
    {
        try (MockedStatic<EntityBuilder> builder = mockStatic(EntityBuilder.class))
        {
            withIssuedObject(builder, USER_ID.toString());

            assertions.whenHandled();
        }
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("missing_kty", body("use", "sig", "kid", "k", "alg", "Ed25519", "crv", "Ed25519", "x", "AAAA")),
                arguments("kty_not_string", body("kty", 5, "use", "sig", "kid", "k", "alg", "Ed25519", "crv", "Ed25519", "x", "AAAA")),
                arguments("kty_unknown", body("kty", "XYZ", "use", "sig", "kid", "k", "alg", "Ed25519", "crv", "Ed25519", "x", "AAAA")),
                arguments("kty_symmetric", body("kty", "oct", "use", "sig", "kid", "k", "alg", "HS256", "k", "AAAA")),
                arguments("missing_use", body("kty", "OKP", "kid", "k", "alg", "Ed25519", "crv", "Ed25519", "x", "AAAA")),
                arguments("use_not_string", body("kty", "OKP", "use", 5, "kid", "k", "alg", "Ed25519", "crv", "Ed25519", "x", "AAAA")),
                arguments("use_not_signature", body("kty", "OKP", "use", "enc", "kid", "k", "alg", "Ed25519", "crv", "Ed25519", "x", "AAAA")),
                arguments("kty_and_use_invalid", body("kty", 5, "use", 5)),
                arguments("missing_crv", body("kty", "OKP", "use", "sig", "kid", "k", "alg", "Ed25519", "x", "AAAA")),
                arguments("crv_not_string", body("kty", "OKP", "use", "sig", "kid", "k", "alg", "Ed25519", "crv", 5, "x", "AAAA")),
                arguments("crv_unknown", body("kty", "OKP", "use", "sig", "kid", "k", "alg", "Ed25519", "crv", "P-999", "x", "AAAA")),
                arguments("crv_of_another_algorithm", body("kty", "OKP", "use", "sig", "kid", "k", "alg", "Ed448", "crv", "Ed25519", "x", "AAAA")),
                arguments("missing_kid", body("kty", "OKP", "use", "sig", "alg", "Ed25519", "crv", "Ed25519", "x", "AAAA")),
                arguments("kid_not_string", body("kty", "OKP", "use", "sig", "kid", 5, "alg", "Ed25519", "crv", "Ed25519", "x", "AAAA")),
                arguments("missing_alg", body("kty", "OKP", "use", "sig", "kid", "k", "crv", "Ed25519", "x", "AAAA")),
                arguments("alg_not_string", body("kty", "OKP", "use", "sig", "kid", "k", "alg", 5, "crv", "Ed25519", "x", "AAAA")),
                arguments("alg_unknown", body("kty", "OKP", "use", "sig", "kid", "k", "alg", "HS256", "crv", "Ed25519", "x", "AAAA")),
                arguments("alg_of_another_type", body("kty", "OKP", "use", "sig", "kid", "k", "alg", "ES256", "crv", "Ed25519", "x", "AAAA")),
                arguments("okp_missing_x", body("kty", "OKP", "use", "sig", "kid", "k", "alg", "Ed25519", "crv", "Ed25519")),
                arguments("okp_x_not_string", body("kty", "OKP", "use", "sig", "kid", "k", "alg", "Ed25519", "crv", "Ed25519", "x", 5)),
                arguments("ec_missing_x_y", body("kty", "EC", "use", "sig", "kid", "k", "alg", "ES256", "crv", "P-256")),
                arguments("rsa_missing_n_e", body("kty", "RSA", "use", "sig", "kid", "k", "alg", "RS256")));
    }

    static Stream<String> testParsingFailure()
    {
        return Stream.of(
                body("kty", null),
                body("kty", DataArray.empty()),
                body("kty", DataObject.empty()),
                body("kty", true),
                body("kty", "OKP", "use", null),
                body("kty", "OKP", "use", DataArray.empty()),
                body("kty", "OKP", "use", "sig", "crv", null),
                body("kty", "OKP", "use", "sig", "crv", DataObject.empty()),
                body("kty", "OKP", "use", "sig", "crv", "Ed25519", "kid", null),
                body("kty", "OKP", "use", "sig", "crv", "Ed25519", "kid", DataArray.empty()),
                body("kty", "OKP", "use", "sig", "crv", "Ed25519", "kid", "k", "alg", null),
                body("kty", "OKP", "use", "sig", "crv", "Ed25519", "kid", "k", "alg", DataObject.empty()),
                body("kty", "OKP", "use", "sig", "crv", "Ed25519", "kid", "k", "alg", "Ed25519", "x", null),
                body("kty", "OKP", "use", "sig", "crv", "Ed25519", "kid", "k", "alg", "Ed25519", "x", DataArray.empty()));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    @Test
    void testNonObject()
    {
        assertThatRequestTo(newAction())
                .withBody(nonObjectBody())
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        assertThatRequestTo(newAction())
                .withBody(mock(RequestBody.class))
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String json)
    {
        withProof(SignType.ED25519);
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testParsingFailure(String json)
    {
        withProof(SignType.ED25519);
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withJsonBody(json)
                .hasFailureMatching(failure -> failure instanceof ErrorResponseException)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @EnumSource(value = SignType.class, mode = EnumSource.Mode.EXCLUDE, names = {"HS256", "HS384", "HS512", "NONE", "UNKNOWN"})
    @ParameterizedTest
    void testKeyType(SignType type)
    {
        AccessEntryData entry = withProof(type);
        ArgumentCaptor<SessionCreateData> created = ArgumentCaptor.forClass(SessionCreateData.class);
        withStoredUser(1);

        whenHandled(assertThatRequestTo(newAction(created))
                .withHeader("User-Agent", USER_AGENT)
                .withJsonBody(entry.toData().toString())
                .hasStatus(StatusReason.CREATED.code)
                .hasContentType(SessionCreateActionImpl.MEDIA_TYPE_ACCESS)
                .hasBodyEqualTo(ISSUED_OBJECT));

        SessionCreateData session = created.getValue();
        assertThat(session.getUserId()).isEqualTo(USER_ID);
        assertThat(session.getSessionId()).isEqualTo(UUIDv7.nameUUIDFromBytes(entry.getPublic().getEncoded()).toUUID());
        assertThat(session.getUserAgent()).isEqualTo(USER_AGENT);
        assertThat(session.getRawSessionFlags()).isZero();
        assertThat(session.getAccessEntry().getPublic().getEncoded()).isEqualTo(entry.getPublic().getEncoded());
        assertThat(session.getThumbprint()).isEqualTo(entry.getContext(AccessContextType.SHA_256).digest());
    }

    @Test
    void testMinimalSession()
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        ArgumentCaptor<SessionCreateData> created = ArgumentCaptor.forClass(SessionCreateData.class);
        withStoredUser(1);

        whenHandled(assertThatRequestTo(newAction(created))
                .withJsonBody(entry.toData().toString())
                .hasStatus(StatusReason.CREATED.code));

        assertThat(created.getValue().getUserId()).isEqualTo(USER_ID);
    }

    @Test
    void testMaxSessions()
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        withStoredUser(SessionAction.MAX_SESSION_COUNT);

        whenHandled(assertThatRequestTo(newAction())
                .withJsonBody(entry.toData().toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot());
    }

    @Test
    void testLastAllowedSession()
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        ArgumentCaptor<SessionCreateData> created = ArgumentCaptor.forClass(SessionCreateData.class);
        withStoredUser(SessionAction.MAX_SESSION_COUNT - 1);

        whenHandled(assertThatRequestTo(newAction(created))
                .withJsonBody(entry.toData().toString())
                .hasStatus(StatusReason.CREATED.code));

        assertThat(created.getAllValues()).hasSize(1);
    }

    @Test
    void testEmptyUser()
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        withStoredUser(0);

        whenHandled(assertThatRequestTo(newAction())
                .withJsonBody(entry.toData().toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot());
    }

    @Test
    void testUnknownUser()
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        whenHandled(assertThatRequestTo(newAction())
                .withJsonBody(entry.toData().toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot());
    }

    @Test
    void testExistingSession()
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        withStoredUser(1);
        SessionCreateActionImpl action = spy(newAction());
        doReturn(failed(new ErrorResponseException(ErrorResponse.ACCESS_ALREADY_EXISTS))).when(action).create(any());

        whenHandled(assertThatRequestTo(action)
                .withJsonBody(entry.toData().toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot());
    }

    @Test
    void testMissingAccess()
    {
        AccessEntryData entry = withProof(SignType.ED25519);

        assertThatRequestTo(newAction())
                .withJsonBody(entry.toData().toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSubject(String name, String subject)
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        withAccess(subject);

        assertThatRequestTo(newAction())
                .withJsonBody(entry.toData().toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().create(null));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCreateApplied() throws Exception
    {
        withJCA();
        InteractionMappingActionImpl<Void> creation = (InteractionMappingActionImpl<Void>) newAction().create(mock(SessionCreateData.class));
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(true);

        creation.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onSuccess(null);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCreateExisting() throws Exception
    {
        withJCA();
        InteractionMappingActionImpl<Void> creation = (InteractionMappingActionImpl<Void>) newAction().create(mock(SessionCreateData.class));
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(false);

        creation.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.ACCESS_ALREADY_EXISTS.getCode()));
    }
}
