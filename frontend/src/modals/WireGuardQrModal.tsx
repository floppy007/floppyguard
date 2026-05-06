import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useEffect, useState } from "react";
import Modal from "react-bootstrap/Modal";
import { getWireGuardLinkConfigQr } from "src/api/backend";
import { Button } from "src/components";
import { T } from "src/locale";

interface Props extends InnerModalProps {
	linkId: string;
	linkName: string;
}

const showWireGuardQrModal = (linkId: string, linkName: string) => {
	EasyModal.show(WireGuardQrModal, { linkId, linkName });
};

const WireGuardQrModal = EasyModal.create(({ linkId, linkName, visible, remove }: Props) => {
	const [qrUrl, setQrUrl] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		if (!visible) return;
		let objectUrl: string | null = null;
		getWireGuardLinkConfigQr(linkId)
			.then((url) => {
				objectUrl = url;
				setQrUrl(url);
			})
			.catch((e) => setError(e.message ?? "Failed to load QR code"));
		return () => {
			if (objectUrl) URL.revokeObjectURL(objectUrl);
		};
	}, [linkId, visible]);

	return (
		<Modal show={visible} onHide={remove} centered>
			<Modal.Header closeButton>
				<Modal.Title className="fs-6">{linkName}</Modal.Title>
			</Modal.Header>
			<Modal.Body className="text-center py-4">
				{error ? (
					<div className="text-danger small">{error}</div>
				) : qrUrl ? (
					<>
						<img
							src={qrUrl}
							alt="WireGuard QR Code"
							style={{ maxWidth: 280, width: "100%", borderRadius: 4 }}
						/>
						<div className="small text-secondary mt-3">
							<T id="wireguard.link.qr-hint" />
						</div>
					</>
				) : (
					<div className="text-secondary small">…</div>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button type="button" actionType="primary" onClick={remove}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export { showWireGuardQrModal };
