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
        this(errorResponse.getCode(), errorResponse.getMeaning(), schemaError);
    }

    public ErrorResponseException(@Nonnull ErrorResponse errorResponse, @Nonnull List<SchemaError> schemaErrors)
    {
        this(errorResponse.getCode(), errorResponse.getMeaning(), schemaErrors);
    }

    public ErrorResponseException(int code, String meaning)
    {
        super(code, meaning);
    }

    public ErrorResponseException(int code, String meaning, @Nonnull SchemaError schemaError)
    {
        super(code, meaning, schemaError);
    }

    public ErrorResponseException(int code, String meaning, @Nonnull List<SchemaError> schemaErrors)
    {
        super(code, meaning, schemaErrors);
    }
}
