package com.github.reganjohn.iam.api.exceptions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;

import javax.annotation.Nonnull;
import java.util.List;

public class ErrorResponseException extends InvalidResponseException
{
    public ErrorResponseException(@Nonnull ErrorResponse errorResponse)
    {
        this(errorResponse.getCode(), errorResponse.getMeaning());
    }

    public ErrorResponseException(@Nonnull ErrorResponse errorResponse, @Nonnull SchemaError schemaError)
    {
        super(errorResponse.getCode(), errorResponse.getMeaning(), schemaError);
    }

    public ErrorResponseException(@Nonnull ErrorResponse errorResponse, @Nonnull List<SchemaError> schemaErrors)
    {
        super(errorResponse.getCode(), errorResponse.getMeaning(), schemaErrors);
    }

    public ErrorResponseException(int code, String meaning)
    {
        super(code, meaning);
    }
}
