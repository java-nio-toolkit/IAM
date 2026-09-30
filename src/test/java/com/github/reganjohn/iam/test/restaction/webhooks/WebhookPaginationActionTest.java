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

package com.github.reganjohn.iam.test.restaction.webhooks;

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.webhooks.WebhookPaginationActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class WebhookPaginationActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID FIRST_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final UUID SECOND_ID = UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d");

    private WebhookPaginationActionImpl newAction()
    {
        return new WebhookPaginationActionImpl(api);
    }

    private void withStoredWebhooks(Webhook... webhooks)
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withWebhooks(user, completed(Arrays.asList(webhooks)));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
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
    void testValidWebhooks()
    {
        withStoredWebhooks(
                withWebhook(FIRST_ID, USER_ID, "first", "avatar-cid", "https://example.org/first", 3, 0),
                withWebhook(SECOND_ID, USER_ID, "second", null, "https://example.org/second", 0, 0));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasContentType(WebhookPaginationActionImpl.MEDIA_TYPE_JSON)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testSingleWebhook()
    {
        withStoredWebhooks(withWebhook(FIRST_ID, USER_ID, "first", null, "https://example.org/first", 0, 0));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testEmpty()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withWebhooks(user, completed(Collections.emptyList()));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testRetrievalFailure()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withWebhooks(user, failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS)));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
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
        withAccess(subject);

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }
}
