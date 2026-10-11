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

package com.github.reganjohn.iam.test.managers;

import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.managers.SessionCryptoManagerImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SessionCryptoManagerTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID SESSION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");

    private final Request request = mock(Request.class);

    private void withToken(String subject, String thumbprint)
    {
        AccessObjectData access = mock(AccessObjectData.class);
        when(access.getSubject()).thenReturn(subject);
        when(access.getThumbprint()).thenReturn(thumbprint);
        channel.attr(AccessOverrideManagerImpl.CONTEXT).set(access);
    }

    private void withStoredSessions(Session... sessions)
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withSessions(user, completed(Arrays.asList(sessions)));
        withRetrieval(USER_ID, completed(user));
    }

    private Throwable handle()
    {
        Throwable thrown = catchThrowable(() -> new SessionCryptoManagerImpl(api).handleSuccess(context, request));
        return thrown != null ? thrown : catchThrowable(channel::checkException);
    }

    private static void assertInvalidToken(Throwable failure)
    {
        assertThat(failure).isInstanceOf(ErrorResponseException.class);
        assertThat(((ErrorResponseException) failure).getErrorCode()).isEqualTo(ErrorResponse.INVALID_TOKEN.getCode());
    }

    @Test
    void testLiveSession()
    {
        withToken(USER_ID.toString(), THUMBPRINT);
        withStoredSessions(withSession(UUID.randomUUID(), USER_ID, "agent", 0, "other"), withSession(SESSION_ID, USER_ID, "agent", 0, THUMBPRINT));

        assertThat(handle()).isNull();
        assertThat((Object) channel.readInbound()).isSameAs(request);
    }

    @Test
    void testRevokedSession()
    {
        withToken(USER_ID.toString(), THUMBPRINT);
        withStoredSessions(withSession(SESSION_ID, USER_ID, "agent", 0, "other"));

        assertInvalidToken(handle());
        assertThat((Object) channel.readInbound()).isNull();
    }

    @Test
    void testWithoutSessions()
    {
        withToken(USER_ID.toString(), THUMBPRINT);
        withStoredSessions();

        assertInvalidToken(handle());
        assertThat((Object) channel.readInbound()).isNull();
    }

    @Test
    void testWithoutThumbprint()
    {
        withToken(USER_ID.toString(), null);
        withStoredSessions(withSession(SESSION_ID, USER_ID, "agent", 0, THUMBPRINT));

        assertInvalidToken(handle());
        assertThat((Object) channel.readInbound()).isNull();
    }

    @Test
    void testUnknownUser()
    {
        withToken(USER_ID.toString(), THUMBPRINT);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        Throwable failure = handle();

        assertThat(failure).isInstanceOf(ErrorResponseException.class);
        assertThat(((ErrorResponseException) failure).getErrorCode()).isEqualTo(ErrorResponse.UNKNOWN_USER.getCode());
        assertThat((Object) channel.readInbound()).isNull();
    }

    @ValueSource(strings = {"", "not-a-uuid", "01a0f15fef227d1e9a96432acf9b644f"})
    @ParameterizedTest
    void testInvalidSubject(String subject)
    {
        withToken(subject, THUMBPRINT);

        assertInvalidToken(handle());
        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testMissingAccess()
    {
        assertInvalidToken(handle());
        verify(api, never()).retrieveUserById(any());
    }
}
