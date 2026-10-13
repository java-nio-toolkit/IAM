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

import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.SessionLogoutActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionListType;
import com.reganjohn.c4j.internal.requests.objaction.InteractionListContextActionImpl;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedConstruction;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class SessionLogoutActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID FIRST_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID SECOND_ID = UUID.fromString("03c2b37b-0144-7f30-9cb8-654ce1bd866b");
    private static final String LOGOUT = "UPDATE users.sessions SET flags = ? WHERE user_id = ? AND session_id = ?";

    private SessionLogoutActionImpl newAction()
    {
        return new SessionLogoutActionImpl(api);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private MockedConstruction<InteractionListContextActionImpl> mockLogout(Throwable failure, List<List<?>> constructions)
    {
        return mockConstruction(InteractionListContextActionImpl.class, (action, context) ->
        {
            constructions.add(context.arguments());
            doAnswer(invocation ->
            {
                if (failure == null)
                    ((Consumer<Object>) invocation.getArgument(0)).accept(null);
                else
                    ((Consumer<Throwable>) invocation.getArgument(1)).accept(failure);
                return null;
            }).when(action).queue(any(), any());
        });
    }

    private UUID withOwnSession(List<Session> others)
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        UUID ownId = UUIDv7.nameUUIDFromBytes(entry.getPublic().getEncoded()).toUUID();
        Session own = withSession(ownId, USER_ID, "Mozilla/5.0", 0, "thumbprint");
        List<Session> sessions = new ArrayList<>(others);
        sessions.add(0, own);
        withSessions(USER_ID, completed(sessions));
        withAccess(USER_ID);
        return ownId;
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
    @SuppressWarnings("rawtypes")
    void testValidSessions()
    {
        Session first = withSession(FIRST_ID, USER_ID, "Mozilla/5.0", 2, "first");
        Session second = withSession(SECOND_ID, USER_ID, null, 0, "second");
        withOwnSession(Arrays.asList(first, second));

        List<List<?>> constructions = new ArrayList<>();
        try (MockedConstruction<InteractionListContextActionImpl> logout = mockLogout(null, constructions))
        {
            assertThatRequestTo(newAction())
                    .hasStatus(StatusReason.NO_CONTENT.code)
                    .hasNoBody()
                    .whenHandled();

            assertThat(constructions).hasSize(1);
            List<?> arguments = constructions.get(0);
            assertThat(arguments.get(1)).isEqualTo(InteractionListType.LOGGED);
            @SuppressWarnings("unchecked")
            ArrayListValuedHashMap<String, List<Object>> statements = (ArrayListValuedHashMap<String, List<Object>>) arguments.get(2);
            assertThat(statements.keySet()).containsExactly(LOGOUT);
            Collection<List<Object>> parameters = statements.get(LOGOUT);
            assertThat(parameters).containsExactlyInAnyOrder(
                    Arrays.asList(2L | Session.SessionFlag.DELETED.getRawValue(), USER_ID, FIRST_ID),
                    Arrays.asList(Session.SessionFlag.DELETED.getRawValue(), USER_ID, SECOND_ID));
        }
    }

    @Test
    @SuppressWarnings("rawtypes")
    void testOwnSessionOnly()
    {
        withOwnSession(Collections.emptyList());

        List<List<?>> constructions = new ArrayList<>();
        try (MockedConstruction<InteractionListContextActionImpl> logout = mockLogout(null, constructions))
        {
            assertThatRequestTo(newAction())
                    .hasNoResponse()
                    .hasFailureOfType(ErrorResponseException.class)
                    .hasFailure(ErrorResponse.CANNOT_CLOSE_SINGLE_SESSION)
                    .whenHandled();

            assertThat(logout.constructed()).isEmpty();
        }
    }

    @Test
    @SuppressWarnings("rawtypes")
    void testLogoutFailure()
    {
        Session first = withSession(FIRST_ID, USER_ID, "Mozilla/5.0", 0, "first");
        withOwnSession(Collections.singletonList(first));

        try (MockedConstruction<InteractionListContextActionImpl> logout = mockLogout(new ErrorResponseException(ErrorResponse.MISSING_ACCESS), new ArrayList<>()))
        {
            assertThatRequestTo(newAction())
                    .hasNoResponse()
                    .hasFailureOfType(ErrorResponseException.class)
                    .hasFailure(ErrorResponse.MISSING_ACCESS)
                    .whenHandled();
        }
    }

    @Test
    void testMissingProof()
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ProofAccessException.class)
                .whenHandled();

        verify(api, never()).retrieveSessions(any());
    }

    @Test
    void testMissingAccess()
    {
        withProof(SignType.ED25519);

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.MISSING_ACCESS)
                .whenHandled();

        verify(api, never()).retrieveSessions(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSubject(String name, String subject)
    {
        withProof(SignType.ED25519);
        withAccess(subject);

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveSessions(any());
    }
}
