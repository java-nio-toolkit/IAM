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

package com.github.reganjohn.iam.test.restaction.interactions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationCallbackResponse;
import com.github.reganjohn.iam.internal.managers.AccessSignatureManagerImpl;
import com.github.reganjohn.iam.internal.requests.restactions.interactions.ApplicationInteractionCallbackActionImpl;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import com.github.reganjohn.iam.test.assertions.restaction.RestActionAssertions;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ApplicationInteractionCallbackActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final UUID INTERACTION_ID = UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d");
    private static final String TOKEN = "continue-token";
    private static final String REFERENCE = "interaction-reference";
    private static final String USER_KEY = "user-jkt";
    private static final long ISSUED_LIFETIME = 900;

    private static final String CLIENT_RAW = newClientRaw();

    private String accessRaw;
    private AccessSignatureManagerImpl signatures;
    private AccessContextData selectedContext;
    private String issuedSubject;
    private UUID issuedActor;
    private DataArray issuedPermissions;

    private ApplicationInteractionCallbackActionImpl newAction()
    {
        return new ApplicationInteractionCallbackActionImpl(api);
    }

    private static String newClientRaw()
    {
        try
        {
            if (Security.getProvider("BC") == null)
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPair pair = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
            return AbstractEntityBuilder.createAccessSecretData(SignType.ED25519.getType(), pair, true)
                    .put("kty", SignType.ED25519.getTypeRaw())
                    .put("alg", SignType.ED25519.getName())
                    .toString();
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
    }

    private void withProofOfClient()
    {
        withProof(SignType.ED25519);
        accessRaw = CLIENT_RAW;
        signatures = mock(AccessSignatureManagerImpl.class);
        when(api.getAccessSignatureManager()).thenReturn(signatures);
    }

    private ApplicationCallbackResponse newResponse(String accessRaw, String continueHash, String reference)
    {
        ApplicationCallbackResponse response = mock(ApplicationCallbackResponse.class);
        InteractionCallbackAction<ApplicationCallbackResponse> deletion = completed(response);
        when(response.getUserId()).thenReturn(USER_ID);
        when(response.getApplicationId()).thenReturn(APPLICATION_ID);
        when(response.getInteractionId()).thenReturn(INTERACTION_ID);
        when(response.getPermissionsRaw()).thenReturn(Permission.VIEW_ACCOUNT.getRawValue());
        when(response.getPermissions()).thenReturn(Permission.getPermissions(Permission.VIEW_ACCOUNT.getRawValue()));
        when(response.getAccessRaw()).thenReturn(DataObject.fromJson(accessRaw));
        when(response.getContinueHash()).thenReturn(continueHash);
        when(response.getInteractionReference()).thenReturn(reference);
        when(response.getThumbprint()).thenReturn(USER_KEY);
        when(response.delete()).thenReturn(deletion);
        return response;
    }

    private ApplicationCallbackResponse newResponse()
    {
        return newResponse(accessRaw, digestOf(TOKEN), REFERENCE);
    }

    private ApplicationInteractionCallbackActionImpl newAction(ApplicationCallbackResponse response)
    {
        ApplicationInteractionCallbackActionImpl action = spy(newAction());
        InteractionCallbackAction<ApplicationCallbackResponse> retrieval = completed(response);
        doReturn(retrieval).when(action).retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);
        return action;
    }

    private static AccessEntryData entryOf(String thumbprint, AccessContextData[] holder)
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(thumbprint);
        AccessEntryData entry = mock(AccessEntryData.class);
        when(entry.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        if (holder != null)
            holder[0] = contextData;
        return entry;
    }

    private AccessContextData withUserKeys(String... thumbprints)
    {
        AccessContextData[] selected = new AccessContextData[1];
        AccessEntryData[] entries = new AccessEntryData[thumbprints.length];
        for (int i = 0; i < thumbprints.length; i++)
            entries[i] = entryOf(thumbprints[i], thumbprints[i].equals(USER_KEY) ? selected : null);
        User user = withUser(USER_ID, "alice", null, 0);
        withAccessEntries(user, completed(new AccessEntryArray(Arrays.asList(entries))));
        withRetrieval(USER_ID, completed(user));
        return selected[0];
    }

    private RestActionAssertions assertThatContinuing(ApplicationInteractionCallbackActionImpl action, String authorization, String json)
    {
        RestActionAssertions assertions = assertThatRequestTo(action)
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .withJsonBody(json);
        return authorization == null ? assertions : assertions.withHeader("Authorization", authorization);
    }

    private RestActionAssertions assertThatContinuing(ApplicationInteractionCallbackActionImpl action)
    {
        return assertThatContinuing(action, "GNAP " + TOKEN, body("interact_ref", REFERENCE));
    }

    private void whenHandled(RestActionAssertions assertions)
    {
        try (MockedStatic<EntityBuilder> built = mockStatic(EntityBuilder.class))
        {
            AccessObjectData issued = mock(AccessObjectData.class);
            when(issued.getRaw()).thenReturn(ISSUED_OBJECT);
            OffsetDateTime issuedAt = OffsetDateTime.now();
            when(issued.getTimeCreated()).thenReturn(issuedAt);
            when(issued.getTimeExpiresAt()).thenReturn(issuedAt.plusSeconds(ISSUED_LIFETIME));
            built.when(() -> EntityBuilder.createObjectData(anyString(), anyString(), anyString(), any(UUID.class),
                            any(DataArray.class), any(AccessEntryManager.class), any(AccessContextData.class), anyString(),
                            any(AccessEntryManagerImpl.AccessEntrySnapshot.class)))
                    .thenAnswer(invocation ->
                    {
                        issuedSubject = invocation.getArgument(2);
                        issuedActor = invocation.getArgument(3);
                        issuedPermissions = invocation.getArgument(4);
                        selectedContext = invocation.getArgument(6);
                        return issued;
                    });

            assertions.whenHandled();
        }
    }

    static Stream<Arguments> testInvalidIds()
    {
        return Stream.of(
                arguments("application_empty", "", INTERACTION_ID.toString()),
                arguments("application_not_uuid", "not-a-uuid", INTERACTION_ID.toString()),
                arguments("application_too_short", "04d3c48c-1255-7041-8dc9", INTERACTION_ID.toString()),
                arguments("interaction_empty", APPLICATION_ID.toString(), ""),
                arguments("interaction_not_uuid", APPLICATION_ID.toString(), "not-a-uuid"),
                arguments("interaction_too_short", APPLICATION_ID.toString(), "05e4d59d-2366-7152-9eda"),
                arguments("both_invalid", "not-a-uuid", "not-a-uuid"));
    }

    static Stream<Arguments> testInvalidBody()
    {
        return Stream.of(
                arguments("empty_object", body()),
                arguments("reference_not_string", body("interact_ref", 5)),
                arguments("reference_empty", body("interact_ref", "")),
                arguments("reference_null", "{\"interact_ref\":null}"),
                arguments("reference_array", body("interact_ref", DataArray.empty())));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidIds(String name, String applicationId, String interactionId)
    {
        withProofOfClient();

        assertThatRequestTo(newAction())
                .withRouteParams(applicationId, interactionId)
                .withHeader("Authorization", "GNAP " + TOKEN)
                .withJsonBody(body("interact_ref", REFERENCE))
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest(name = "{0}")
    void testInvalidBody(String name, String json)
    {
        withProofOfClient();

        assertThatContinuing(newAction(), "GNAP " + TOKEN, json)
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testNonObject()
    {
        withProofOfClient();

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .withHeader("Authorization", "GNAP " + TOKEN)
                .withBody(nonObjectBody())
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        withProofOfClient();

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .withHeader("Authorization", "GNAP " + TOKEN)
                .withBody(mock(RequestBody.class))
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testSignatureNonceChallenge() throws Exception
    {
        withProofOfClient();
        doThrow(new ProofAccessException("iam", "use_dpop_nonce", "A DPoP nonce is required for this request.", "nonce")).when(signatures).verify(any(), any(), any(DataObject.class));
        ApplicationCallbackResponse response = newResponse();

        assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasFailureOfType(ProofAccessException.class)
                .whenHandled();

        verify(response, never()).delete();
    }

    @ValueSource(strings = {"", "GNAP", "GNAP ", "Bearer continue-token", "DPoP continue-token", "GNAP first second", "continue-token"})
    @ParameterizedTest
    void testMalformedAuthorization(String authorization)
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();

        assertThatContinuing(newAction(response), authorization, body("interact_ref", REFERENCE))
                .hasInteractionResponse(InteractionResponse.INVALID_CONTINUATION, ErrorResponse.UNKNOWN_TOKEN)
                .hasNoResponse()
                .whenHandled();

        verify(response, never()).delete();
    }

    @Test
    void testMissingAuthorization()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();

        assertThatContinuing(newAction(response), null, body("interact_ref", REFERENCE))
                .hasInteractionResponse(InteractionResponse.INVALID_CONTINUATION, ErrorResponse.UNKNOWN_TOKEN)
                .hasNoResponse()
                .whenHandled();

        verify(response, never()).delete();
    }

    @Test
    void testValidContinuation()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        AccessContextData userContext = withUserKeys("another-jkt", USER_KEY, "third-jkt");

        whenHandled(assertThatContinuing(newAction(response))
                .hasStatus(StatusReason.OK.code)
                .hasContentType(ApplicationInteractionCallbackActionImpl.MEDIA_TYPE_JSON)
                .hasJsonBody(json ->
                {
                    assertThat(json.toMap().keySet()).containsExactly("access_token");
                    DataObject token = json.getObject("access_token");
                    assertThat(token.toMap().keySet()).containsExactlyInAnyOrder("value", "access", "key", "expires_in");
                    assertThat(token.getString("value")).isEqualTo(ISSUED_OBJECT);
                    assertThat(token.getString("key")).isEqualTo(USER_KEY);
                    assertThat(token.getLong("expires_in")).isEqualTo(ISSUED_LIFETIME);
                    assertThat(token.getArray("access").toString())
                            .isEqualTo(PermissionUtil.toDataArray(Permission.getPermissions(Permission.VIEW_ACCOUNT.getRawValue())).toString());
                }));

        verify(response).delete();
        assertThat(issuedSubject).isEqualTo(USER_ID.toString());
        assertThat(issuedActor).isEqualTo(APPLICATION_ID);
        assertThat(issuedPermissions.toString()).isEqualTo(PermissionUtil.toDataArray(Permission.getPermissions(Permission.VIEW_ACCOUNT.getRawValue())).toString());
        assertThat(selectedContext).isSameAs(userContext);
    }

    @Test
    void testLabelIsEchoed()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        when(response.getLabel()).thenReturn("my-token");
        withUserKeys(USER_KEY);

        whenHandled(assertThatContinuing(newAction(response))
                .hasStatus(StatusReason.OK.code)
                .hasJsonBody(json ->
                {
                    DataObject token = json.getObject("access_token");
                    assertThat(token.toMap().keySet()).containsExactlyInAnyOrder("value", "access", "key", "expires_in", "label");
                    assertThat(token.getString("label")).isEqualTo("my-token");
                }));
    }

    @Test
    void testSchemeIsCaseInsensitive()
    {
        withProofOfClient();
        withUserKeys(USER_KEY);

        whenHandled(assertThatContinuing(newAction(newResponse()), "gnap " + TOKEN, body("interact_ref", REFERENCE))
                .hasStatus(StatusReason.OK.code));
    }

    @Test
    void testUnknownInteraction()
    {
        withProofOfClient();
        ApplicationInteractionCallbackActionImpl action = spy(newAction());
        InteractionCallbackAction<ApplicationCallbackResponse> retrieval = failed(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
        doReturn(retrieval).when(action).retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);

        assertThatContinuing(action)
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CONTINUATION, ErrorResponse.UNKNOWN_TOKEN)
                .whenHandled();
    }

    @Test
    void testOtherRetrievalFailure()
    {
        withProofOfClient();
        ApplicationInteractionCallbackActionImpl action = spy(newAction());
        InteractionCallbackAction<ApplicationCallbackResponse> retrieval = failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS));
        doReturn(retrieval).when(action).retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);

        assertThatContinuing(action)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .whenHandled();
    }

    @Test
    void testRejectedSignature() throws Exception
    {
        withProofOfClient();
        doThrow(new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)).when(signatures).verify(any(), any(), any(DataObject.class));
        ApplicationCallbackResponse response = newResponse();

        assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(response, never()).delete();
    }

    @Test
    void testAnotherToken()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse(accessRaw, digestOf("another-token"), REFERENCE);

        assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CONTINUATION, ErrorResponse.UNKNOWN_TOKEN)
                .whenHandled();

        verify(response, never()).delete();
    }

    @ValueSource(strings = {"another-reference", "INTERACTION-REFERENCE", "interaction-reference "})
    @ParameterizedTest
    void testAnotherReference(String reference)
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();

        assertThatContinuing(newAction(response), "GNAP " + TOKEN, body("interact_ref", reference))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_INTERACTION, ErrorResponse.UNKNOWN_INTERACTION)
                .whenHandled();

        verify(response, never()).delete();
    }

    @Test
    void testClientIsCheckedFirst() throws Exception
    {
        withProofOfClient();
        doThrow(new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)).when(signatures).verify(any(), any(), any(DataObject.class));
        ApplicationCallbackResponse response = newResponse(accessRaw, digestOf("another-token"), "another-reference");

        assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)
                .whenHandled();
    }

    @Test
    void testUserKeyIsGone()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        withUserKeys("another-jkt");

        whenHandled(assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_INTERACTION, ErrorResponse.UNKNOWN_INTERACTION));

        verify(response, never()).delete();
    }

    @Test
    void testUnknownUser()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        whenHandled(assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class));

        verify(response, never()).delete();
    }

    @Test
    void testDeleteFailure()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        InteractionCallbackAction<ApplicationCallbackResponse> deletion = failed(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
        when(response.delete()).thenReturn(deletion);
        withUserKeys(USER_KEY);

        whenHandled(assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class));

        assertThat(issuedSubject).isEqualTo(USER_ID.toString());
    }

    @Test
    void testUserDenied()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        when(response.isDenied()).thenReturn(true);

        whenHandled(assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.USER_DENIED, ErrorResponse.MISSING_ACCESS));

        verify(response).delete();
    }

    @Test
    void testDeniedIsNotIssued()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        when(response.isDenied()).thenReturn(true);

        whenHandled(assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.USER_DENIED, ErrorResponse.MISSING_ACCESS));

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testDeniedReferenceIsChecked()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        when(response.isDenied()).thenReturn(true);

        assertThatContinuing(newAction(response), "GNAP " + TOKEN, body("interact_ref", "another-reference"))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_INTERACTION, ErrorResponse.UNKNOWN_INTERACTION)
                .whenHandled();

        verify(response, never()).delete();
    }

    @Test
    void testDeniedDeleteFailure()
    {
        withProofOfClient();
        ApplicationCallbackResponse response = newResponse();
        when(response.isDenied()).thenReturn(true);
        InteractionCallbackAction<ApplicationCallbackResponse> deletion = failed(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
        when(response.delete()).thenReturn(deletion);

        whenHandled(assertThatContinuing(newAction(response))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class));
    }

    @Test
    void testCallbackStatement()
    {
        withJCA();

        InteractionContextActionImpl<?> retrieval = (InteractionContextActionImpl<?>) newAction().retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);

        assertThat(retrieval.getContent()).contains("SELECT * FROM integrations.responses", "application_id = ?", "interaction_id = ?");
        assertThat(retrieval.getElements()).containsExactly(APPLICATION_ID, INTERACTION_ID);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCallbackMissing() throws Exception
    {
        withJCA();
        InteractionContextActionImpl<ApplicationCallbackResponse> retrieval = (InteractionContextActionImpl<ApplicationCallbackResponse>) newAction().retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);
        InteractionImpl<ApplicationCallbackResponse> interaction = mock(InteractionImpl.class);
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(true);

        retrieval.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.UNKNOWN_INTERACTION.getCode()));
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().retrieveCallbackResponse(null, INTERACTION_ID));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().retrieveCallbackResponse(APPLICATION_ID, null));
    }
}
