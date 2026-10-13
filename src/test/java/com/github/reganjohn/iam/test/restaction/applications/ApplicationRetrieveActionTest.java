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

package com.github.reganjohn.iam.test.restaction.applications;

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.applications.ApplicationRetrieveActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
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

public class ApplicationRetrieveActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");

    private ApplicationRetrieveActionImpl newAction()
    {
        return new ApplicationRetrieveActionImpl(api);
    }

    private void withStoredApplication(UUID applicationId, Application application)
    {
        withApplication(USER_ID, applicationId, completed(application));
        withAccess(USER_ID);
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty", "", "application_id=BASE_TYPE_REQUIRED"),
                arguments("not_uuid", "not-a-uuid", "application_id=UUID_TYPE_COERCE"),
                arguments("too_short", "04d3c48c-1255-7041-8dc9", "application_id=UUID_TYPE_COERCE"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", "application_id=UUID_TYPE_COERCE"),
                arguments("without_dashes", "04d3c48c125570418dc9765df2ce977c", "application_id=UUID_TYPE_COERCE"));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String applicationId, String errors)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(applicationId)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFormErrors(errors.split("[=,]"))
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveApplicationById(any(), any());
    }

    @ValueSource(strings = {
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "04D3C48C-1255-7041-8DC9-765DF2CE977C",
            "04d3c48c-1255-7041-8dc9-765df2ce977c"})
    @ParameterizedTest
    void testValidInputs(String applicationId)
    {
        UUID id = UUID.fromString(applicationId);
        withStoredApplication(id, withApplication(id, USER_ID, "app", null, null, "https://example.org", 0, "https://example.org/callback"));

        assertThatRequestTo(newAction())
                .withRouteParams(applicationId)
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        verify(api).retrieveApplicationById(USER_ID, id);
    }

    @Test
    void testValidApplication()
    {
        withStoredApplication(APPLICATION_ID, withApplication(APPLICATION_ID, USER_ID, "app", "description", "avatar-cid", "https://example.org", 0, "https://example.org/callback"));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasContentType(ApplicationRetrieveActionImpl.MEDIA_TYPE_JSON)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMinimalApplication()
    {
        withStoredApplication(APPLICATION_ID, withApplication(APPLICATION_ID, USER_ID, "app", null, null, "https://example.org", 0, "https://example.org/callback"));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownApplication()
    {
        withApplication(USER_ID, APPLICATION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION)));
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_APPLICATION)
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.MISSING_ACCESS)
                .whenHandled();

        verify(api, never()).retrieveApplicationById(any(), any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSubject(String name, String subject)
    {
        withAccess(subject);

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveApplicationById(any(), any());
    }
}
