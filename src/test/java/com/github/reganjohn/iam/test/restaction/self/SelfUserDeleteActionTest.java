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

package com.github.reganjohn.iam.test.restaction.self;

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserDeleteActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SelfUserDeleteActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");

    private SelfUserDeleteActionImpl newAction()
    {
        return new SelfUserDeleteActionImpl(api);
    }

    @ValueSource(strings = {
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "01A0F15F-EF22-7D1E-9A96-432ACF9B644F",
            "01a0f15f-ef22-7d1e-9a96-432acf9b644f"})
    @ParameterizedTest
    void testValidInputs(String subject)
    {
        UUID id = UUID.fromString(subject);
        User user = withUser(id, "alice", null, 0);
        withAccess(subject);
        withRetrieval(completed(user));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        verify(api).retrieveUserById(id);
        verify(user).delete();
    }

    @Test
    void testValidUser()
    {
        User user = withUser(USER_ID, "alice", "avatar-cid", 5);
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.NO_CONTENT.code)
                .hasNoBody()
                .whenHandled();

        verify(user).delete();
    }

    @Test
    void testUnknownUser()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_USER)
                .whenHandled();

        verify(user, never()).delete();
    }

    @Test
    void testDeleteFailure()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        InteractionCallbackAction<Void> deletion = failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS));
        when(user.delete()).thenReturn(deletion);
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.MISSING_ACCESS)
                .whenHandled();
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
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.MISSING_ACCESS)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
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

        verify(api, never()).retrieveUserById(any());
    }
}
