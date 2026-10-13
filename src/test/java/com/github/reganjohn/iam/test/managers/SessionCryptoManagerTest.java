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
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.managers.SessionCryptoManagerImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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

    private final Request request = mock(Request.class);

    private void withToken(String subject, String thumbprint)
    {
        AccessObjectData access = mock(AccessObjectData.class);
        when(access.getSubject()).thenReturn(subject);
        when(access.getThumbprint()).thenReturn(thumbprint);
        channel.attr(AccessOverrideManagerImpl.CONTEXT).set(access);
    }

    private UUID withSessionId()
    {
        AccessEntryData entry = withProof(SignType.ES256);
        return UUIDv7.nameUUIDFromBytes(entry.getPublic().getEncoded()).toUUID();
    }

    private void withStoredSession(InteractionCallbackAction<Session> session)
    {
        UUID sessionId = withSessionId();
        when(api.retrieveSessionById(USER_ID, sessionId)).thenReturn(session);
        withRetrieval(USER_ID, completed(withUser(USER_ID, "alice", null, 0)));
    }

    private void withStoredSession(String thumbprint)
    {
        withStoredSession(completed(withSession(UUID.randomUUID(), USER_ID, "agent", 0, thumbprint)));
    }

    private Throwable handle()
    {
        Throwable thrown = catchThrowable(() -> new SessionCryptoManagerImpl(api).handleSuccess(context, request));
        return thrown != null ? thrown : catchThrowable(channel::checkException);
    }

    private static void assertError(Throwable failure, ErrorResponse expected)
    {
        assertThat(failure).isInstanceOf(ErrorResponseException.class);
        assertThat(((ErrorResponseException) failure).getErrorCode()).isEqualTo(expected.getCode());
    }

    @Test
    void testLiveSession()
    {
        withToken(USER_ID.toString(), THUMBPRINT);
        withStoredSession(THUMBPRINT);

        assertThat(handle()).isNull();
        assertThat((Object) channel.readInbound()).isSameAs(request);
    }

    @Test
    void testRevokedSession()
    {
        withToken(USER_ID.toString(), THUMBPRINT);
        withStoredSession(failed(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION)));

        assertError(handle(), ErrorResponse.INVALID_TOKEN);
        assertThat((Object) channel.readInbound()).isNull();
    }

    @Test
    void testOtherThumbprint()
    {
        withToken(USER_ID.toString(), THUMBPRINT);
        withStoredSession("other");

        assertError(handle(), ErrorResponse.INVALID_TOKEN);
        assertThat((Object) channel.readInbound()).isNull();
    }

    @Test
    void testWithoutThumbprint()
    {
        withToken(USER_ID.toString(), null);
        withStoredSession(THUMBPRINT);

        assertError(handle(), ErrorResponse.INVALID_TOKEN);
        assertThat((Object) channel.readInbound()).isNull();
    }

    @Test
    void testSessionFailure()
    {
        IllegalStateException failure = new IllegalStateException();
        withToken(USER_ID.toString(), THUMBPRINT);
        withStoredSession(failed(failure));

        assertThat(handle()).isSameAs(failure);
        assertThat((Object) channel.readInbound()).isNull();
    }

    @Test
    void testUnknownUser()
    {
        withToken(USER_ID.toString(), THUMBPRINT);
        withStoredSession(failed(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION)));
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertError(handle(), ErrorResponse.UNKNOWN_USER);
        assertThat((Object) channel.readInbound()).isNull();
    }

    @ValueSource(strings = {"", "not-a-uuid", "01a0f15fef227d1e9a96432acf9b644f"})
    @ParameterizedTest
    void testInvalidSubject(String subject)
    {
        withToken(subject, THUMBPRINT);
        withProof(SignType.ES256);

        assertError(handle(), ErrorResponse.INVALID_TOKEN);
        verify(api, never()).retrieveUserById(any());
        verify(api, never()).retrieveSessionById(any(), any());
    }

    @Test
    void testMissingProof()
    {
        withToken(USER_ID.toString(), THUMBPRINT);

        assertError(handle(), ErrorResponse.INVALID_TOKEN);
        verify(api, never()).retrieveUserById(any());
        verify(api, never()).retrieveSessionById(any(), any());
    }

    @Test
    void testMissingAccess()
    {
        withProof(SignType.ES256);

        assertError(handle(), ErrorResponse.INVALID_TOKEN);
        verify(api, never()).retrieveUserById(any());
    }
}
