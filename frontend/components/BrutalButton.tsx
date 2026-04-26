'use client'
import { ButtonHTMLAttributes, useState } from 'react'

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'green' | 'red' | 'amber'
  loading?: boolean
  loadingText?: string
}

export default function BrutalButton({
  children,
  variant = 'default',
  loading,
  loadingText = '[ EXECUTING... ]',
  className = '',
  disabled,
  ...rest
}: Props) {
  const [clicked, setClicked] = useState(false)

  const colorMap = {
    default: 'brutal-btn',
    green:   'brutal-btn green',
    red:     'brutal-btn red',
    amber:   'brutal-btn amber',
  }

  function handleClick(e: React.MouseEvent<HTMLButtonElement>) {
    setClicked(true)
    setTimeout(() => setClicked(false), 200)
    rest.onClick?.(e)
  }

  const isLoading = loading || clicked
  const label = isLoading ? loadingText : children

  return (
    <button
      {...rest}
      onClick={handleClick}
      disabled={disabled || loading}
      className={`${colorMap[variant]} ${className}`}
      style={{ fontFamily: 'inherit', ...rest.style }}
    >
      {label}
    </button>
  )
}
