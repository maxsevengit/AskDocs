import React, { forwardRef } from 'react';

const Input = forwardRef(({
    label,
    error,
    className = '',
    id,
    type = 'text',
    ...props
}, ref) => {
    return (
        <div className="w-full">
            {label && (
                <label htmlFor={id} className="block text-sm font-medium text-slate-700 mb-1.5">
                    {label}
                </label>
            )}
            <div className="relative">
                <input
                    ref={ref}
                    id={id}
                    type={type}
                    className={`
            block w-full rounded-lg border-slate-300 shadow-sm 
            focus:border-primary-500 focus:ring-primary-500 
            disabled:bg-slate-50 disabled:text-slate-500
            transition-colors duration-200
            ${error ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''}
            ${className}
          `}
                    {...props}
                />
            </div>
            {error && (
                <p className="mt-1 text-sm text-red-600">{error}</p>
            )}
        </div>
    );
});

Input.displayName = 'Input';

export default Input;
