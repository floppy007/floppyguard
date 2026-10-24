import { T } from "src/locale";
import { showCustomCertificateModal, showDNSCertificateModal, showHTTPCertificateModal } from "src/modals";
import { POPPER_FIXED } from "src/modules/Dropdown";

interface Props {
	className?: string;
}

// "Add certificate" dropdown (HTTP / DNS / Custom), shared by the table header and the empty state
export default function AddCertificateDropdown({ className = "" }: Props) {
	return (
		<div className="dropdown">
			<button
				type="button"
				className={`btn dropdown-toggle btn-pink ${className}`.trim()}
				data-bs-toggle="dropdown"
				data-bs-popper-config={POPPER_FIXED}
			>
				<T id="object.add" tData={{ object: "certificate" }} />
			</button>
			<div className="dropdown-menu">
				<a
					className="dropdown-item"
					href="#"
					onClick={(e) => {
						e.preventDefault();
						showHTTPCertificateModal();
					}}
				>
					<T id="lets-encrypt-via-http" />
				</a>
				<a
					className="dropdown-item"
					href="#"
					onClick={(e) => {
						e.preventDefault();
						showDNSCertificateModal();
					}}
				>
					<T id="lets-encrypt-via-dns" />
				</a>
				<div className="dropdown-divider" />
				<a
					className="dropdown-item"
					href="#"
					onClick={(e) => {
						e.preventDefault();
						showCustomCertificateModal();
					}}
				>
					<T id="certificates.custom" />
				</a>
			</div>
		</div>
	);
}
