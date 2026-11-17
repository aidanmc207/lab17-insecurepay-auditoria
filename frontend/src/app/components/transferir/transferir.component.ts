import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { BancoService } from '../../services/banco.service';
import { AuthService } from '../../services/auth.service';
import { Cuenta, TransferenciaRequest } from '../../models/banco.model';

@Component({
  selector: 'app-transferir',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
  templateUrl: './transferir.component.html'
})
export class TransferirComponent implements OnInit {
  misCuentas: Cuenta[] = [];
  transferencia: TransferenciaRequest = {
    cuentaOrigenId: 0,
    numeroCuentaDestino: '',
    monto: 0,
    conceptoHtml: ''
  };

  loading = false;
  errorMsg = '';
  successMsg = '';

  constructor(
    private bancoService: BancoService,
    public authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    // [REMEDIACION IDOR] Solo se ofrecen como origen las cuentas del usuario autenticado
    const user = this.authService.currentUser();
    if (!user) return;
    this.bancoService.obtenerCuentasUsuario(user.usuarioId).subscribe({
      next: (cuentas) => {
        this.misCuentas = cuentas;
        if (cuentas.length > 0) {
          this.transferencia.cuentaOrigenId = cuentas[0].id;
        }
      },
      error: (err) => {
        this.errorMsg = 'No fue posible cargar sus cuentas: ' + (err.error?.detail || 'intente de nuevo.');
      }
    });
  }

  onTransferir(): void {
    if (!this.transferencia.cuentaOrigenId || !this.transferencia.numeroCuentaDestino || !this.transferencia.monto) {
      this.errorMsg = 'Por favor complete todos los datos de la transferencia.';
      return;
    }

    this.loading = true;
    this.errorMsg = '';
    this.successMsg = '';

    this.bancoService.transferir(this.transferencia).subscribe({
      next: (res) => {
        this.loading = false;
        this.successMsg = `¡Transferencia exitosa! Débito de ₡${res.monto} ejecutado en la cuenta origen #${res.cuentaOrigenId}.`;
        setTimeout(() => {
          this.router.navigate(['/transacciones']);
        }, 1500);
      },
      error: (err) => {
        this.loading = false;
        this.errorMsg = 'Error en la transacción: ' + (err.error?.detail || 'intente de nuevo.');
      }
    });
  }

  inyectarPayload(tipo: string): void {
    if (tipo === 'alert') {
      this.transferencia.conceptoHtml = `<img src="invalido" onerror="alert('Alerta Forense: Ejecución XSS en Comprobante InsecurePay!')">`;
    } else if (tipo === 'html') {
      this.transferencia.conceptoHtml = `<div style="background: #fee2e2; border: 2px solid red; padding: 10px; border-radius: 6px;">` +
        `<h4 style="color: #991b1b; margin:0;">ALERTA DE SEGURIDAD</h4>` +
        `<p style="margin: 4px 0 0; color: #7f1d1d;">Transferencia con concepto no verificado sanitariamente.</p></div>`;
    }
  }
}

