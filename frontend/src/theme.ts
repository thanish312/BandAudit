import { createTheme } from "@mui/material/styles";
import type {} from "@mui/x-data-grid/themeAugmentation";

const fontFamily = "Inter, -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif";

const typeTokens = {
  fontFamily,
  caption: "0.72rem",
  small: "0.75rem",
  body: "0.8125rem",
  bodyLarge: "0.92rem",
  section: "1rem",
  page: "1.35rem",
  title: "1.72rem",
  score: "2.25rem",
  weightRegular: 400,
  weightMedium: 500,
  weightSemibold: 600,
  weightBold: 700,
  leadingTight: 1.2,
  leadingNormal: 1.45,
  leadingRelaxed: 1.6
};

export const auditTheme = createTheme({
  cssVariables: true,
  palette: {
    mode: "light",
    primary: {
      main: "#14783E",
      dark: "#0F5F32",
      light: "#E7F5EC",
      contrastText: "#FFFFFF"
    },
    error: {
      main: "#B42318",
      dark: "#7A271A",
      light: "#FEE4E2",
      contrastText: "#FFFFFF"
    },
    warning: {
      main: "#B54708",
      dark: "#7A2E0E",
      light: "#FEF0C7",
      contrastText: "#111827"
    },
    success: {
      main: "#067647",
      dark: "#085D3A",
      light: "#DCFAE6",
      contrastText: "#FFFFFF"
    },
    info: {
      main: "#175CD3",
      light: "#D1E9FF",
      dark: "#1849A9",
      contrastText: "#FFFFFF"
    },
    background: {
      default: "#F7F8FA",
      paper: "#FFFFFF"
    },
    text: {
      primary: "#101828",
      secondary: "#475467",
      disabled: "#98A2B3"
    },
    divider: "#E4E7EC"
  },
  shape: {
    borderRadius: 10
  },
  typography: {
    fontFamily,
    h1: {
      fontSize: typeTokens.title,
      fontWeight: typeTokens.weightBold,
      letterSpacing: 0,
      lineHeight: 1.14
    },
    h2: {
      fontSize: typeTokens.page,
      fontWeight: typeTokens.weightBold,
      letterSpacing: 0,
      lineHeight: 1.18
    },
    h3: {
      fontSize: typeTokens.section,
      fontWeight: typeTokens.weightSemibold,
      letterSpacing: 0,
      lineHeight: 1.28
    },
    h4: {
      fontSize: "1.5rem",
      fontWeight: typeTokens.weightBold,
      letterSpacing: 0,
      lineHeight: 1.2
    },
    h5: {
      fontSize: "1.25rem",
      fontWeight: typeTokens.weightBold,
      letterSpacing: 0,
      lineHeight: 1.22
    },
    subtitle2: {
      fontSize: typeTokens.caption,
      fontWeight: typeTokens.weightSemibold,
      letterSpacing: "0.045em",
      textTransform: "uppercase",
      lineHeight: 1.35
    },
    body1: {
      fontSize: typeTokens.bodyLarge,
      lineHeight: 1.5,
      letterSpacing: 0
    },
    body2: {
      fontSize: typeTokens.body,
      lineHeight: typeTokens.leadingNormal,
      letterSpacing: 0
    },
    caption: {
      fontSize: typeTokens.caption,
      lineHeight: 1.35,
      letterSpacing: 0
    },
    button: {
      fontWeight: typeTokens.weightSemibold,
      letterSpacing: 0,
      textTransform: "none"
    }
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        ":root": {
          "--audit-font-family": typeTokens.fontFamily,
          "--audit-type-caption": typeTokens.caption,
          "--audit-type-small": typeTokens.small,
          "--audit-type-body": typeTokens.body,
          "--audit-type-body-lg": typeTokens.bodyLarge,
          "--audit-type-section": typeTokens.section,
          "--audit-type-page": typeTokens.page,
          "--audit-type-title": typeTokens.title,
          "--audit-type-score": typeTokens.score,
          "--audit-weight-regular": String(typeTokens.weightRegular),
          "--audit-weight-medium": String(typeTokens.weightMedium),
          "--audit-weight-semibold": String(typeTokens.weightSemibold),
          "--audit-weight-bold": String(typeTokens.weightBold),
          "--audit-leading-tight": String(typeTokens.leadingTight),
          "--audit-leading-normal": String(typeTokens.leadingNormal),
          "--audit-leading-relaxed": String(typeTokens.leadingRelaxed)
        },
        body: {
          minWidth: 320,
          overflowX: "hidden",
          backgroundColor: "#F7F8FA"
        },
        "*": {
          boxSizing: "border-box"
        }
      }
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          boxShadow: "none",
          borderColor: "#E4E7EC"
        }
      }
    },
    MuiCard: {
      defaultProps: {
        variant: "outlined"
      },
      styleOverrides: {
        root: {
          boxShadow: "none",
          borderColor: "#E4E7EC"
        }
      }
    },
    MuiButton: {
      defaultProps: {
        size: "small",
        disableElevation: true
      },
      styleOverrides: {
        root: {
          minHeight: 34,
          borderRadius: 8,
          textTransform: "none",
          fontSize: typeTokens.body,
          fontWeight: typeTokens.weightSemibold
        }
      }
    },
    MuiIconButton: {
      defaultProps: {
        size: "small"
      },
      styleOverrides: {
        root: {
          borderRadius: 8
        }
      }
    },
    MuiChip: {
      defaultProps: {
        size: "small"
      },
      styleOverrides: {
        root: {
          height: 22,
          borderRadius: 999,
          fontSize: typeTokens.caption,
          fontWeight: typeTokens.weightSemibold
        },
        label: {
          display: "inline-flex",
          alignItems: "center",
          lineHeight: 1,
          minHeight: "100%"
        }
      }
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: 8
        }
      }
    },
    MuiDivider: {
      styleOverrides: {
        root: {
          borderColor: "#E4E7EC"
        }
      }
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderColor: "#E4E7EC",
          padding: "10px 14px"
        },
        head: {
          color: "#475467",
          fontSize: typeTokens.caption,
          fontWeight: typeTokens.weightSemibold
        },
        body: {
          color: "#101828",
          fontSize: typeTokens.body
        }
      }
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: 8
        }
      }
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundImage: "none",
          boxShadow: "none",
          borderColor: "#E4E7EC"
        }
      }
    },
    MuiMenu: {
      styleOverrides: {
        paper: {
          border: "1px solid #E4E7EC",
          boxShadow: "0 12px 32px rgba(16, 24, 40, 0.12)"
        }
      }
    },
    MuiMenuItem: {
      styleOverrides: {
        root: {
          minHeight: 34,
          fontSize: typeTokens.body
        }
      }
    },
    MuiDataGrid: {
      styleOverrides: {
        root: {
          borderColor: "#E4E7EC",
          color: "#101828",
          backgroundColor: "#FFFFFF",
          "--DataGrid-rowBorderColor": "#E4E7EC"
        },
        columnHeaders: {
          backgroundColor: "#F9FAFB",
          color: "#475467"
        },
        columnHeaderTitle: {
          fontSize: typeTokens.caption,
          fontWeight: typeTokens.weightSemibold
        },
        cell: {
          fontSize: typeTokens.body
        }
      }
    }
  }
});

export const appTheme = auditTheme;
