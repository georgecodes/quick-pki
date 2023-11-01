package com.elevenware.pki;

import org.junit.Rule;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512;

@Testcontainers
public class KmsTests {

    DockerImageName localstackImage = DockerImageName.parse("localstack/localstack:0.11.3");

    @Container
    public LocalStackContainer localstack = new LocalStackContainer(localstackImage)
            .withServices(LocalStackContainer.Service.KMS)
//            .waitingFor(new HttpWaitStrategy().forPort(8080))
            ;


    @Test
    void test() throws Exception {


        KmsClient client = KmsClient.builder()
                .endpointOverride(localstack.getEndpointOverride(LocalStackContainer.Service.KMS))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(localstack.getAccessKey(), localstack.getSecretKey())))
                .region(Region.of(localstack.getRegion()))
                .build();

        String alias = "alias/digning-key";
        CreateKeyRequest keyRequest = CreateKeyRequest.builder()
                .description("signing key")
                .customerMasterKeySpec(CustomerMasterKeySpec.RSA_2048)
                .keyUsage("SIGN_VERIFY")
                .build();

        CreateKeyResponse result = client.createKey(keyRequest);
        String keyId = result.keyMetadata().keyId();

        CreateAliasRequest aliasRequest = CreateAliasRequest.builder()
                .aliasName(alias)
                .targetKeyId(keyId)
                .build();

        client.createAlias(aliasRequest);

        String rawMessage = "Hello";
        MessageDigest digester = MessageDigest.getInstance("SHA-512");

        byte[] messageDigest = digester.digest(rawMessage.getBytes(StandardCharsets.UTF_8));

        SigningAlgorithmSpec signingAlgorithmSpec = RSASSA_PKCS1_V1_5_SHA_512;

        SignRequest signReq =
                 SignRequest.builder()
                        .keyId(alias)
                        .messageType(MessageType.DIGEST)
                        .message(SdkBytes.fromByteArray(messageDigest))
                         .signingAlgorithm(signingAlgorithmSpec)
                         .build();

        SignResponse signResult = client.sign(signReq);

        byte[] signatureBytes = signResult.signature().asByteArray();
        VerifyRequest verifyRequest = VerifyRequest.builder()
                .keyId(alias)
                .messageType(MessageType.DIGEST)
                .message(SdkBytes.fromByteArray(messageDigest))
                .signature(signResult.signature())
                .signingAlgorithm(signingAlgorithmSpec)
                .build();

        VerifyResponse verifyResponse = client.verify(verifyRequest);

        SigningAlgorithmSpec signingAlgorithmSpecUsed = verifyResponse.signingAlgorithm();
        assertEquals(signingAlgorithmSpec, signingAlgorithmSpecUsed);


    }

}
