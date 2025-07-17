import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';
import { ResponseUtil } from '../utils/response';

export const validateRequest = (schema: {
  body?: ZodSchema;
  params?: ZodSchema;
  query?: ZodSchema;
}) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      // Validate request body
      if (schema.body) {
        req.body = schema.body.parse(req.body);
      }

      // Validate request params
      if (schema.params) {
        req.params = schema.params.parse(req.params);
      }

      // Validate request query
      if (schema.query) {
        req.query = schema.query.parse(req.query);
      }

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const errorMessages = error.errors.map((err) => ({
          field: err.path.join('.'),
          message: err.message,
        }));

        return ResponseUtil.badRequest(
          res,
          'Validation failed',
          JSON.stringify(errorMessages)
        );
      }

      return ResponseUtil.badRequest(res, 'Invalid request data');
    }
  };
}; 