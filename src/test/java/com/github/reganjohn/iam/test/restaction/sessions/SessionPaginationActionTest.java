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

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.SessionPaginationActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SessionPaginationActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID FIRST_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID SECOND_ID = UUID.fromString("03c2b37b-0144-7f30-9cb8-654ce1bd866b");

    private SessionPaginationActionImpl newAction()
    {
        return new SessionPaginationActionImpl(api);
    }

    private static AccessEntryData entryOf(String thumbprint, String kid)
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(thumbprint);
        AccessEntryData entry = mock(AccessEntryData.class);
        when(entry.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        when(entry.toData()).thenReturn(DataObject.empty().put("kty", "OKP").put("kid", kid));
        return entry;
    }

    private void withStoredSessions(AccessEntryArray entries, Session... sessions)
    {
        InteractionCallbackAction<List<Session>> stored = completed(Arrays.asList(sessions));
        InteractionCallbackAction<AccessEntryArray> access = completed(entries);
        withSessions(USER_ID, stored);
        withAccessEntries(USER_ID, access);
        withAccess(USER_ID);
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
    void testValidSessions()
    {
        Session first = withSession(FIRST_ID, USER_ID, "Mozilla/5.0", 2, "first");
        Session second = withSession(SECOND_ID, USER_ID, "curl/8.0", 0, "second");
        AccessEntryArray entries = new AccessEntryArray(Arrays.asList(
                entryOf("first", "first-key"), entryOf("second", "second-key"), entryOf("unrelated", "unrelated-key")));
        withStoredSessions(entries, first, second);

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasContentType(SessionPaginationActionImpl.MEDIA_TYPE_JSON)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMinimalSessions()
    {
        Session first = withSession(FIRST_ID, USER_ID, null, 0, "first");
        withStoredSessions(new AccessEntryArray(Collections.singletonList(entryOf("first", "first-key"))), first);

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testEmpty()
    {
        withStoredSessions(new AccessEntryArray(Collections.emptyList()));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasBodyEqualTo("[]")
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
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
        withAccess(subject);

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveSessions(any());
    }
}
